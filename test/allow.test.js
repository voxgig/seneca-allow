/* Copyright (c) 2018 voxgig and other contributors, MIT License */
'use strict'

const Util = require('util')

const _ = require('lodash')

const Lab = require('lab')
const Code = require('code')
const lab = (exports.lab = Lab.script())
const expect = Code.expect

const PluginValidator = require('seneca-plugin-validator')
const Seneca = require('seneca')
const Plugin = require('..')
const Store = require('../lib/store')


lab.test('validate', PluginValidator(Plugin, module))


// NEXT: validate perm op access - all scenarios


lab.test('happy', fin => {
  const permspecs = {
    'aaa': {
      perms: [
        // usr$ is the inbound context, usr is the data field
        // they must match to give use access to own data
        {p:{usr$:'aaa',usr:'aaa'}, v:true},
      ]
    },
    'bbb': {
      perms: [
        {p:{usr$:'bbb',usr:'bbb'}, v:true},
      ]
    },
  }

  Seneca()
    .test('silent')
    //.test('print')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs
    })
    .ready(function() {
      var aaa = this.delegate({usr:'aaa'})
      var bbb = this.delegate({usr:'bbb'})

      aaa
        .make$('foo', {id$:1, mark:'a', usr:'aaa'})
        .save$(function (err, foo, meta) {
          if(err) return fin(err)
          expect(foo.mark).equal('a')
          expect(meta).exists()
          
          aaa
            .make$('foo')
            .load$(1,function (err, foo2) {
              expect(foo2.mark).equal('a')
              expect(foo2.id).equal(foo.id)
              
              bbb
                .make$('foo')
                .load$(1,function (err, foo) {
                  expect(err.code).equal('no_read_access')
                  expect(foo).not.exist()
                  fin()
                })
            })
        })
    })
})


lab.test('edges', fin => {
  const permspecs = {}

  Seneca()
    .test(fin)
    //.test('print')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs
    })
    .ready(function() {
      var aaa = this.delegate({usr:'aaa'})
      var bbb = this.delegate({usr:'bbb'})

      // creates an entry for the 'aaa' user
      // by default user owns anything they create
      this.act(
        'role:allow,upon:perm,op:add,tusr:aaa',
        {perm:{p:{usr$:'aaa',usr:'aaa'},v:true}},
        function(err, out) {
          expect(out)
            .equal({ perms: [ { p: { 'usr$': 'aaa', usr: 'aaa' }, v: true } ],
                     'usr$': 'aaa' })
          expect(d(this).aaa).equal(out)

          // creates a group 'nopermsatall' with no perms
          // as null == perm param
          this.act(
            'role:allow,upon:perm,op:add,tgrp:nopermsatall',
            function(err, out) {
              expect(out).equal({ perms: [], 'grp$': 'nopermsatall' })
              expect(d(this).nopermsatall).equal(out)

              // creates an entry for the 'purples' org
              // by default all perms denied, forces whitelist
              this.act(
                'role:allow,upon:perm,op:add,torg:purples',
                {perm:{p:{org$:'purples'},v:false}},
                function(err, out) {
                  expect(out)
                    .equal({ perms: [ { p: { 'org$': 'purples' }, v: false } ],
                             'org$': 'purples' })
                  expect(d(this).purples).equal(out)
              
                  fin()
                })
            })
        })
    })
})



lab.test('org-admin', fin => {
  const permspecs = {
    'ccc': {
      perms: [
        {p:{usr$:'ccc',usr:'ccc'}, v:true},
        // NOTE: this is not the standard way, just for testing
        // See below for normal org/group
        {p:{org$:'QQQ'}, v:true},
      ]
    },
    'ddd': {
      perms: [
        {p:{usr$:'ddd',usr:'ddd'}, v:true},
        {p:{org$:'QQQ'}, v:true},
      ]
    },
  }

  Seneca()
    .test('silent')
    //.test('print')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs
    })
    .use(function () {
      this
        .add('role:entity,cmd:save',function(msg,reply){
          msg.ent.usr = msg.usr
          msg.ent.org = msg.org
          this.prior(msg,reply)
        })
    })
    .ready(function() {
      var ccc = this.delegate({usr:'ccc', org:'QQQ'})
      var ddd = this.delegate({usr:'ddd', org:'QQQ'})

      ccc
        .make$('bar', {id$:1, mark:'b'})//, usr:'ccc', org:'QQQ'})
        .save$(function (err, bar) {
          if(err) return fin(err)
          expect(bar.mark).equal('b')
          
          ccc
            .make$('bar')
            .load$(1,function (err, bar2) {
              expect(bar2.mark).equal('b')
              expect(bar2.id).equal(bar.id)
              
              ddd
                .make$('bar')
                .load$(1,function (err, bar3) {
                  expect(bar3.mark).equal('b')
                  expect(bar3.id).equal(bar.id)

                  fin()
                })
            })
        })
    })
})


const permspecs_alice_bob_org0 = {
  'alice': {usr$:'alice', perms: [{p:{usr$:'alice',usr:'alice'}, v:true}]},
  'bob': {usr$:'bob', perms: [{p:{usr$:'bob',usr:'bob'}, v:true}]},
  
  // This is an important default, forces perms into groups
  'org0': {org$:'org0', perms: [{p:{org$:'org0'}, v:false}]},
  'admin0': {grp:'admin0', perms: [{p:{}, v:true}]},
  'read0': {grp:'read0', perms: [
    {p:{ent$:true,cmd$:'load'}, v:true}
  ]},
  
  'alice~org0':{usr$:'alice', org$:'org0', grps: ['admin0']},
  'bob~org0':{usr$:'bob', org$:'org0', grps: ['read0']},
}


lab.test('resolve_perms', fin => {

  Seneca()
    .test(fin)
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs_alice_bob_org0
    })
    .ready(function() {
      var exp = this.export('allow')

      exp.resolve_perms(this,{usr:'alice'},function(ignore, out){
        //console.log(out)
        expect(out.find({usr$:'alice',usr:'alice'})).equal(true)
        
        exp.resolve_perms(this,{usr:'alice',org:'org0'},function(ignore, out){
          //console.log(out)
          expect(out.find({usr$:'alice',org$:'org0'})).equal(true)
          
          exp.resolve_perms(this,{usr:'bob'},function(ignore, out){
            //console.log(out)
            expect(out.find({usr$:'bob',usr:'bob'})).equal(true)
            
            exp.resolve_perms(this,{usr:'bob',org:'org0'},function(ignore, out){
              //console.log(out)
              expect(out.find({usr$:'bob',org$:'org0'})).equal(false)
              expect(out.find({usr$:'bob',org$:'org0',cmd$:'load',ent$:true})).equal(true)
              expect(out.find({usr$:'bob',org$:'org0',cmd$:'save',ent$:true})).equal(false)

              fin()
            })
          })
        })
      })
    })
})


lab.test('access-org-basic', fin => {

  Seneca()
    //.test('print')
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs_alice_bob_org0
    })
    .use(function () {
      this
        .add('role:entity,cmd:save',function(msg,reply){
          msg.ent.usr = msg.usr
          msg.ent.org = msg.org
          this.prior(msg,reply)
        })
    })
    .ready(function() {
      var alice_org0 = this.delegate({usr:'alice', org:'org0'})
      var bob_org0 = this.delegate({usr:'bob', org:'org0'})

      // alice can write
      alice_org0
        .make$('zed', {id$:1, mark:'a'})
        .save$(function (err, zed) {
          if(err) return fin(err)
          expect(zed).exist()

          // bob can't write
          bob_org0
            .make$('zed', {id$:2, mark:'b'})
            .save$(function (err, zed) {
              //console.log(err,zed)
              expect(err.code).equal('no_write_access')
              expect(zed).not.exist()

              // alice can read
              alice_org0
                .make$('zed')
                .load$({id:1}, function(err, zed){
                  //console.log(zed)
                  if(err) return fin(err)
                  expect(zed).exist()

                  // bob can read
                  bob_org0
                    .make$('zed')
                    .load$({id:1}, function(err, zed){
                      //console.log(zed)
                      if(err) return fin(err)
                      expect(zed).exist()
                      
                      fin()
                    })
                })
            })
        })
    })
})



lab.test('access-org-field', fin => {

  const permspecs_alice_bob_org1 = {
    'alice': {usr$:'alice', perms: [{p:{usr$:'alice',usr:'alice'}, v:true}]},
    'bob': {usr$:'bob', perms: [{p:{usr$:'bob',usr:'bob'}, v:true}]},
    
    // This is an important default, forces perms into groups
    'org1': {org$:'org1', perms: [{p:{org$:'org1'}, v:false}]},
    'admin0': {grp:'admin0', perms: [{p:{}, v:true}]},
    'read1': {grp:'read1', perms: [
      {p:{ent$:true,cmd$:'load',mark:'a'}, v:true}
    ]},
    
    'alice~org1':{usr$:'alice', org$:'org1', grps: ['admin0']},
    'bob~org1':{usr$:'bob', org$:'org1', grps: ['read1']},
  }

  Seneca()
    //.test('print')
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs_alice_bob_org1
    })
    .use(function () {
      this
        .add('role:entity,cmd:save',function(msg,reply){
          msg.ent.usr = msg.usr
          msg.ent.org = msg.org
          this.prior(msg,reply)
        })
    })
    .ready(function() {
      var alice_org1 = this.delegate({usr:'alice', org:'org1'})
      var bob_org1 = this.delegate({usr:'bob', org:'org1'})

      // alice can write
      alice_org1
        .make$('zed', {id$:1, mark:'a'})
        .save$(function (err, zed) {
          if(err) return fin(err)
          expect(zed).exist()

          alice_org1
            .make$('zed', {id$:2, mark:'b'})
            .save$(function (err, zed) {
              if(err) return fin(err)
              expect(zed).exist()

              do_access(alice_org1, bob_org1)
            })
        })
      
      function do_access(alice_org1, bob_org1) {
        // bob can't write
        bob_org1
          .make$('zed', {id$:2, mark:'a'})
          .save$(function (err, zed) {
            //console.log(err,zed)
            expect(err.code).equal('no_write_access')
            expect(zed).not.exist()
            
            // alice can read
            alice_org1
              .make$('zed')
              .load$({id:1}, function(err, zed){
                //console.log(zed)
                if(err) return fin(err)
                expect(zed).exist()
                
                // bob can't read mark:b
                bob_org1
                  .make$('zed')
                  .load$({id:2}, function(err, zed){
                    //console.log(zed)
                    expect(err.code).equal('no_read_access')
                    expect(zed).not.exist()

                    // bob can read mark:a
                    bob_org1
                      .make$('zed')
                      .load$({id:1}, function(err, zed){
                        //console.log(zed)
                        expect(err).not.exist()
                        expect(zed).exist()
                        fin()
                      })
                  })
              })
          })
      }
    })
})



lab.test('access-org-readwrite', fin => {

  const permspecs_alice_bob_org2 = {
    'alice': {usr$:'alice', perms: [{p:{usr$:'alice',usr:'alice'}, v:true}]},
    'bob': {usr$:'bob', perms: [{p:{usr$:'bob',usr:'bob'}, v:true}]},
    'cathy': {usr$:'cathy', perms: [{p:{usr$:'catch',usr:'cathy'}, v:true}]},
    
    // This is an important default, forces perms into groups
    'org2': {org$:'org2', perms: [{p:{org$:'org2'}, v:false}]},

    // the admin pseudo-group for org2
    'admin': {grp:'admin', perms: [
      {p:{}, v:true},
    ]},

    // the write pseudo-group for org2
    'write-a': {grp:'write-a', perms: [
      {p:{ent$:true,cmd$:'save',mark:'a'}, v:true},
      {p:{ent$:true,cmd$:'remove',mark:'a'}, v:true},
      {p:{ent$:true,cmd$:'load',mark:'a'}, v:true},
      {p:{ent$:true,cmd$:'list',mark:'a'}, v:true}
    ]},

    // the read pseudo-group for org2
    'read-a': {grp:'read-a', perms: [
      {p:{ent$:true,cmd$:'load',mark:'a'}, v:true},
      {p:{ent$:true,cmd$:'list',mark:'a'}, v:true}
    ]},
    
    'alice~org2':{usr$:'alice', org$:'org2', grps: ['write-a']},
    'bob~org2':{usr$:'bob', org$:'org2', grps: ['read-a']},
    'cathy~org2':{usr$:'cathy', org$:'org2', grps: ['admin']},
  }

  Seneca()
    //.test('print')
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs_alice_bob_org2
    })
    .use(function () {
      this
        .add('role:entity,cmd:save',function(msg,reply){
          msg.ent.usr = msg.usr
          msg.ent.org = msg.org
          this.prior(msg,reply)
        })
    })
    .ready(function() {
      var alice_org2 = this.delegate({usr:'alice', org:'org2'})
      var bob_org2 = this.delegate({usr:'bob', org:'org2'})
      var cathy_org2 = this.delegate({usr:'cathy', org:'org2'})

      // alice can write a
      alice_org2
        .make$('qaz', {id$:1, mark:'a'})
        .save$(function (err, qaz1) {
          if(err) return fin(err)
          expect(qaz1).exist()

          // alice can't write b
          alice_org2
            .make$('qaz', {id$:2, mark:'b'})
            .save$(function (err, qaz2) {
              expect(err.code).equal('no_write_access')
              expect(qaz2).not.exist()

              // alice can write a
              alice_org2
                .make$('qaz', {id$:3, mark:'a'})
                .save$(function (err, qaz3) {
                  if(err) return fin(err)
                  expect(qaz3).exist()

                  // cathy can write anything
                  cathy_org2
                    .make$('qaz', {id$:2, mark:'b'})
                    .save$(function (err, qaz2) {
                      if(err) return fin(err)
                      expect(qaz2).exist()

                      do_access(alice_org2, bob_org2, cathy_org2)
                    })
                })
            })
        })
      
      function do_access(alice_org2, bob_org2, cathy_org2) {
        // bob can't write
        bob_org2
          .make$('qaz', {id$:4, mark:'a'})
          .save$(function (err, qaz4) {
            //console.log(err,qaz)
            expect(err.code).equal('no_write_access')
            expect(qaz4).not.exist()
            
            // alice can read
            alice_org2
              .make$('qaz')
              .load$({id:1}, function(err, qaz){
                //console.log(qaz)
                if(err) return fin(err)
                expect(qaz).exist()
                
                // bob can't read mark:b
                bob_org2
                  .make$('qaz')
                  .load$({id:2}, function(err, qaz2){
                    //console.log(qaz)
                    expect(err.code).equal('no_read_access')
                    expect(qaz2).not.exist()

                    // bob can read mark:a
                    bob_org2
                      .make$('qaz')
                      .load$({id:3}, function(err, qaz3){
                        //console.log(qaz)
                        expect(err).not.exist()
                        expect(qaz3).exist()

                        do_list(alice_org2, bob_org2, cathy_org2)
                      })
                  })
              })
          })
      }

      function do_list(alice_org2, bob_org2, cathy_org2) {
        // alice lists 1,3
        alice_org2
          .make$('qaz')
          .list$({}, function(err, list0){
            expect(err).not.exist()
            expect(list0.length).equal(2)
            expect(list0[0].id).equal(1)
            expect(list0[1].id).equal(3)

            // bob lists 1,3
            bob_org2
              .make$('qaz')
              .list$({}, function(err, list1){
                expect(err).not.exist()
                expect(list1.length).equal(2)
                expect(list1[0].id).equal(1)
                expect(list1[1].id).equal(3)

                // cathy lists 1,2,3
                cathy_org2
                  .make$('qaz')
                  .list$({}, function(err, list2){
                    expect(err).not.exist()
                    expect(list2.length).equal(3)
                    expect(list2[0].id).equal(1)
                    expect(list2[1].id).equal(2)
                    expect(list2[2].id).equal(3)

                    fin()
                  })
              })
          })
      }
    })
})


lab.test('access-msg', fin => {

  const permspecs_org3 = {
    'alice': {usr$:'alice', perms: [{p:{usr$:'alice',usr:'alice'}, v:true}]},
    'bob': {usr$:'bob', perms: [{p:{usr$:'bob',usr:'bob'}, v:true}]},
    
    // This is an important default, forces perms into groups
    'org3': {org$:'org3', perms: [{p:{org$:'org3'}, v:false}]},

    // the admin pseudo-group for org2
    'canfoo': {grp:'canfoo', perms: [
      {p:{role:'bar',cmd:'foo'}, v:true},
    ]},
    
    'alice~org3':{usr$:'alice', org$:'org3', grps: ['canfoo']}
  }

  Seneca()
    //.test('print')
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs_org3,
      pins:[{role:'bar',cmd:'foo'}]
    })
    .add('role:bar,cmd:foo', function(msg, reply) {
      reply({zed:msg.zed})
    })
    .ready(function() {
      var alice_org3 = this.delegate({usr:'alice', org:'org3'})
      var bob_org3 = this.delegate({usr:'bob', org:'org3'})

      alice_org3.act('role:bar,cmd:foo,zed:a', function(err, out) {
        expect(err).not.exist()
        expect(out.zed).equal('a')

        bob_org3.act('role:bar,cmd:foo,zed:a', function(err, out) {
          expect(err.code).equal('no_in_access')
          expect(out).not.exist()

          fin()
        })
      })
    })
})



lab.test('intern-get_perms', fin => {
  const permspecs = {
    alice: {perms:[{p:{usr$:'alice'},v:true}]},

    'aaa': {org$:'aaa',perms:[{p:{org$:'aaa'},v:false}]},
    'g0': {grp:'g0',org$:'aaa',perms:[{p:{color:'red'},v:true}]},
    
    bob: {usr$:'bob',perms:[{p:{usr$:'bob'},v:true}]},
    'bob~aaa': {usr$:'bob',org$:'aaa',grps:['g0']},

  }
  
  const store = Store({permspecs:permspecs})

  Plugin.intern.get_perms(store,{usr:'alice'},function(err,out){
    if(err) return fin(err)
    expect(out.perms[0].p.usr$).equal('alice')

    Plugin.intern.get_perms(store,{usr:'bob', org:'aaa'},function(err,out){
      if(err) return fin(err)
      //console.dir(out,{depth:null})
      expect(out.perms[0].p.usr$).equal('bob')
      expect(out.perms[1].p.org$).equal('aaa')
      expect(out.perms[1].v).equal(false)
      expect(out.perms[2].p).equal({ color: 'red', usr$: 'bob', org$: 'aaa' })
      
      fin()
    })
  })
})


lab.test('intern-make_perms_key', fin => {
  // NOTE: this are all IDs, not names
  expect(Plugin.intern.make_perms_key({usr:'a'})).equals('a')
  expect(Plugin.intern.make_perms_key({org:'b'})).equals('b')
  expect(Plugin.intern.make_perms_key({usr:'x',org:'y'})).equals('x~y')
  expect(function(){Plugin.intern.make_perms_key({})}).throws()
  expect(Plugin.intern.make_perms_key({grp:'g'})).equals('g')
  fin()
})

lab.test('intern-make_grps_key', fin => {
  // NOTE: this are all IDs, not names
  expect(Plugin.intern.make_grps_key({usr:'a',org:'b'})).equals('a~b')
  expect(function(){Plugin.intern.make_grps_key({})}).throws()
  expect(function(){Plugin.intern.make_grps_key({usr:'a'})}).throws()
  expect(function(){Plugin.intern.make_grps_key({org:'b'})}).throws()
  expect(function(){Plugin.intern.make_grps_key({usr:'',org:'b'})}).throws()
  expect(function(){Plugin.intern.make_grps_key({usr:'a',org:''})}).throws()
  expect(function(){Plugin.intern.make_grps_key({grp:'c'})}).throws()
  fin()
})


lab.test('intern-grp', fin => {
  var store = Store({permspecs:{
    'alice~reds': {usr$:'alice', org$:'reds', grps:['g0']}
  }})

  Plugin.intern.get_grps(store, {usr:'alice', org:'reds'}, function(err, out) {
    if(err) return fin(err)
    expect(out).equal({ usr: 'alice', org: 'reds', grps: [ 'g0' ] })

    Plugin.intern.grp_update(
      store, {op:'add',tusr:'alice', torg:'reds', tgrp:'g1'},
      function(err, out) {
        if(err) return fin(err)
        expect(out).equal({ grps: [ 'g0', 'g1' ], 'usr$': 'alice', 'org$': 'reds' })

        Plugin.intern.grp_update(
          store, {op:'rem',tusr:'alice', torg:'reds', tgrp:'g0'},
          function(err, out) {
            if(err) return fin(err)
            expect(out).equal({ grps: [ 'g1' ], 'usr$': 'alice', 'org$': 'reds' })

            fin()
          })
      })
  })
})


lab.test('intern-perm', fin => {
  var store = Store()

  Plugin.intern.perm_update(
    store,
    {tusr:'alice', op:'add',
     perm:{p:{ent$:true, usr$:'alice', usr:'alice'},v:true}},
    function(err, out) {
      if(err) return fin(err)
      //console.dir(out,{depth:null})
      expect(out).equal({ perms: [ { p: { 'ent$': true, 'usr$': 'alice', usr: 'alice' }, v: true } ], 'usr$': 'alice' })

      // Maintain uniqueness
      Plugin.intern.perm_update(
        store,
        {tusr:'alice', op:'add',
         perm:{p:{ent$:true, usr$:'alice', usr:'alice'},v:true}},
        function(err, out) {
          if(err) return fin(err)
          //console.dir(out,{depth:null})
          expect(out).equal({ perms: [ { p: { 'ent$': true, 'usr$': 'alice', usr: 'alice' }, v: true } ], 'usr$': 'alice' })

          do_grp()
        })
    })

  function do_grp() {
    Plugin.intern.perm_update(
      store,
      {tgrp:'g0', op:'add',
       perm:{p:{ent$:true, cmd$:'load'},v:true}},
      function(err, out) {
        if(err) return fin(err)
        //console.dir(out,{depth:null})
        expect(out).equal({ perms: [ { p: { 'ent$': true, 'cmd$': 'load' }, v: true } ], 'grp$': 'g0' })

        Plugin.intern.perm_update(
          store,
          {tgrp:'g0', op:'add',
           perm:{p:{ent$:true, cmd$:'save'},v:true}},
          function(err, out) {
            if(err) return fin(err)
            //console.dir(out,{depth:null})
            expect(out).equal({ perms: 
                                [ { p: { 'ent$': true, 'cmd$': 'load' }, v: true },
                                  { p: { 'ent$': true, 'cmd$': 'save' }, v: true } ],
                                'grp$': 'g0' })
            


            Plugin.intern.perm_update(
              store,
              {tgrp:'g0', op:'add',
               perm:{p:{ent$:true, cmd$:'list'},v:true}},
              function(err, out) {
                if(err) return fin(err)
                //console.dir(out,{depth:null})
                expect(out).equal({
                  perms: 
                  [ { p: { 'ent$': true, 'cmd$': 'load' }, v: true },
                    { p: { 'ent$': true, 'cmd$': 'save' }, v: true },
                    { p: { 'ent$': true, 'cmd$': 'list' }, v: true } ],
                  'grp$': 'g0' })

                Plugin.intern.perm_update(
                  store,
                  {tgrp:'g0', op:'rem',
                   perm:{p:{ent$:true, cmd$:'save'},v:true}},
                  function(err, out) {
                    if(err) return fin(err)
                    //console.dir(out,{depth:null})
                    expect(out).equal({
                      perms: 
                      [ { p: { 'ent$': true, 'cmd$': 'load' }, v: true },
                        { p: { 'ent$': true, 'cmd$': 'list' }, v: true } ],
                      'grp$': 'g0' })
                
                    fin()
                  })
              })
          })
      })
    }
  })



lab.test('store', fin => {
  const permspecs = {
    'aaa': {
      perms: [
        // usr$ is the inbound context, usr is the data field
        // they must match to give use access to own data
        {p:{usr$:'aaa',usr:'aaa'}, v:true},
      ]
    },
    'bbb': {
      perms: [
        {p:{usr$:'bbb',usr:'bbb'}, v:true},
      ]
    },
  }

  Seneca()
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
    })

    .use(function extstore() {
      this.add('init:extstore', function(msg, reply) {
        var store = Store({tag:'loaded',permspecs:permspecs})
        this.export('allow').store(store)
        reply()
      })
    })

    .ready(function() {
      expect(this.export('allow').store().tag).equal('loaded')

      var aaa = this.delegate({usr:'aaa'})
      var bbb = this.delegate({usr:'bbb'})

      aaa
        .make$('foo', {id$:1, mark:'a', usr:'aaa'})
        .save$(function (err, foo, meta) {
          if(err) return fin(err)
          expect(foo.mark).equal('a')
          expect(meta).exists()
          
          aaa
            .make$('foo')
            .load$(1,function (err, foo2) {
              expect(foo2.mark).equal('a')
              expect(foo2.id).equal(foo.id)
              
              bbb
                .make$('foo')
                .load$(1,function (err, foo) {
                  expect(err.code).equal('no_read_access')
                  expect(foo).not.exist()
                  fin()
                })
            })
        })
    })
})


lab.test('network', fin => {
  const permspecs = {
    'aaa': {
      perms: [
        {p:{usr$:'aaa',usr:'aaa'}, v:true},
      ]
    },
    'bbb': {
      perms: [
        {p:{usr$:'bbb',usr:'bbb'}, v:true},
      ]
    },
  }

  Seneca({tag:'server'})
    .test('silent')
    //.test('print')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs
    })
    .listen({pin:{role:'allow'}})

  Seneca({tag:'client'})
    .test('silent')
    //.test('print')
    .use('entity')
    .use(Plugin)
    .client({pin:{role:'allow'}})
    .ready(function() {
      var aaa = this.delegate({usr:'aaa'})
      var bbb = this.delegate({usr:'bbb'})

      aaa
        .make$('foo', {id$:1, mark:'a', usr:'aaa'})
        .save$(function (err, foo, meta) {
          if(err) return fin(err)
          expect(foo.mark).equal('a')
          expect(meta).exists()
          
          aaa
            .make$('foo')
            .load$(1,function (err, foo2) {
              expect(foo2.mark).equal('a')
              expect(foo2.id).equal(foo.id)
              
              bbb
                .make$('foo')
                .load$(1,function (err, foo) {
                  expect(err.code).equal('no_read_access')
                  expect(foo).not.exist()
                  fin()
                })
            })
        })
    })
})



lab.test('perm-access', fin => {
  // TODO: admin users in org can set perms for others
  // TODO: normal users in org cannot set perms for others
  // TODO: normal users in org can set perms for specific ents

  const permspecs = {
    // alice will an admin for 'greens' org
    'alice': {usr$:'alice', perms: [{p:{usr$:'alice',usr:'alice'}, v:true}]},

    // bob is an 'owner' for 'greens' org - can assign groups
    'bob': {usr$:'bob', perms: [{p:{usr$:'bob',usr:'bob'}, v:true}]},

    // cathy is a user for 'greens' assigned to groups by bob
    'cathy': {usr$:'cathy', perms: [{p:{usr$:'catch',usr:'cathy'}, v:true}]},

    // an organisation
    'greens': {org$:'greens', perms: [{p:{org$:'greens'}, v:false}]},

    // the admin group for greens
    'admin': {grp$:'admin', org$:'greens', perms: [
      {p:{org$:'greens'}, v:true},
    ]},

    // the owner group for greens: full ent access; can assign groups
    'owner': {grp$:'owner', org$:'greens', perms: [
      {p:{role:'allow',upon:'grp',op:'*',org$:'greens'}, v:true},
      {p:{ent$:true,cmd$:'*',org$:'greens'}, v:true},
    ]},

    // the owner group for 'bar' ents with field mark=a in 'greens':
    // ent access only to bar{mark=a}; assign only group 'write-bar-a'
    'owner-bar-a': {grp$:'owner-bar-a', org$:'greens', perms: [
      {p:{role:'allow',upon:'grp',op:'*',org$:'greens',grp$:'write-bar-a'}, v:true},
      {p:{ent$:true,cmd$:'*',org$:'greens',name$:'bar',mark:'a'}, v:true},
    ]},

    // write group for 'greens'
    'write': {grp$:'write', org$:'greens', perms: [
      {p:{ent$:true,cmd$:'*',org$:'greens'}, v:true},
    ]},

    // write group for 'greens', but only on ent bar with field mark=a
    'write-bar-a': {grp$:'write-bar-a', org$:'greens', perms: [
      {p:{ent$:true,cmd$:'*',org$:'greens',name$:'bar',mark:'a'}, v:true},
    ]},

    // alice group assignments in 'greens'
    'alice~greens':{usr$:'alice', org$:'greens', grps: ['admin']},
  }


  Seneca()
    //.test('print')
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      permspecs: permspecs,
      pins:[
        // activity construction for group assignments
        {role:'allow',upon:'grp',op:'*',
         make_activity$:function(activity,mode,msg){
           activity.org$ = msg.torg
           activity.grp$ = msg.tgrp
           activity.op = msg.op
           return activity
         }
        }
      ]

    })
    .use(function () {
      // set usr and org fields on an ent when saving
      this
        .add('role:entity,cmd:save',function(msg,reply){
          msg.ent.usr = msg.usr
          msg.ent.org = msg.org
          this.prior(msg,reply)
        })
    })
    .ready(function() {
      var alice = this.delegate({usr:'alice', org:'greens'})
      var bob   = this.delegate({usr:'bob', org:'greens'})
      var cathy = this.delegate({usr:'cathy', org:'greens'})
      var derek = this.delegate({usr:'derek', org:'greens'})
      var eoin  = this.delegate({usr:'eoin', org:'greens'})
      var fred  = this.delegate({usr:'fred', org:'greens'})

      // alice can save anything
      alice.make$('foo',{id$:1,a:1}).save$(function(err, out) {
        if(err) return fin(err)
        expect(out.a).equal(1)

        // bob cannot yet add cathy to write group
        bob.act(
          'role:allow,upon:grp,op:add,tgrp:write,tusr:cathy,torg:greens',
          function(err, out) {
            expect(err.code).equal('no_in_access')

            // alice adds bob to owner group in org greens
            alice.act(
              'role:allow,upon:grp,op:add,tgrp:owner,tusr:bob,torg:greens',
              function(err, out) {
                expect(out)
                  .equal({ grps: [ 'owner' ], 'usr$': 'bob', 'org$': 'greens' })

                // alice can't access 'blues' org, she's only an admin for 'greens'
                alice.act(
                  'role:allow,upon:grp,op:add,tgrp:owner,tusr:bob,torg:blues',
                  function(err, out) {
                    expect(err.code).equal('no_in_access')

                    do_owner_bob()
                  })
              })
          })
      })

      function do_owner_bob() {
        //console.dir(bob.export('allow').store().data(),{depth:null})
        
        bob.act('role:allow,get:perms', function(err, out){
          expect(out.perms).equal([
            // from bob
            { p: { 'usr$': 'bob', usr: 'bob' }, v: true },

            // from org
            { p: { 'org$': 'greens' }, v: false },

            // from owner group
            { p: { role: 'allow', upon: 'grp', op: '*',
                   'org$': 'greens', 'usr$': 'bob' }, v: true },
            { p: { 'ent$': true, 'cmd$': '*', 'org$': 'greens', 'usr$': 'bob' },
              v: true } ])

          // assign cathy to write group
          bob.act(
            'role:allow,upon:grp,op:add,tgrp:write,tusr:cathy,torg:greens',
            function(err, out) {
              expect(out)
                .equal({ grps: [ 'write' ], 'usr$': 'cathy', 'org$': 'greens' })
              expect(this.export('allow').store().data()['cathy~greens'].grps)
                .equal(['write'])
              
              // can't assign cathy to write group in 'blues' org
              this.act(
                'role:allow,upon:grp,op:add,tgrp:write,tusr:cathy,torg:blues',
                function(err, out) {
                  expect(err.code).equal('no_in_access')
                  
                  // cathy can write as in `write` group
                  cathy.make$('foo',{id$:2,a:2}).save$(function(err, out) {
                    if(err) return fin(err)
                    expect(out.a).equal(2)

                    // bob creates a read group
                    // IRL you'll need to add cmd:list too as another msg
                    bob.act(
                      'role:allow,upon:perm,op:add,tgrp:read,torg:greens',
                      {perm:{ p: { 'ent$': true, 'cmd$': 'load',
                                   'org$': 'greens' },
                              v: true }},
                      function(err, out) {
                        expect(out).equal(
                          { perms: 
                            [ { p: { 'ent$': true, 'cmd$': 'load', 'org$': 'greens' },
                                v: true } ],
                            'org$': 'greens',
                            'grp$': 'read' })
                        expect(d(this).read).equal(out)

                        // assign fred to read group
                        bob.act(
                          'role:allow,upon:grp,op:add,tgrp:read,'+
                            'tusr:fred,torg:greens',
                          function(err, out) {
                            expect(out).equal(
                              { grps: [ 'read' ], 'usr$': 'fred', 'org$': 'greens' })
                            expect(d(this)['fred~greens'].grps)
                              .equal(['read'])

                            // fred can read as in `read` group
                            fred.make$('foo').load$({id:2},function(err, out) {
                              if(err) return fin(err)
                              expect(out.a).equal(2)

                              // fred can't write
                              fred
                                .make$('foo',{id$:3,a:3})
                                .save$(function(err, out) {
                                  expect(err.code).equal('no_write_access')

                                  do_bar()
                                })
                            })
                          })
                      })
                  })
                })
            })
        })
      }

      function do_bar() {
        eoin.make$('bar',{id$:1,mark:'a'}).save$(function(err, out) {
          expect(err).exist()
          
          alice.act(
            'role:allow,upon:grp,op:add,tgrp:owner-bar-a,tusr:derek,torg:greens',
            function(err, out) {
              expect(out)
                .equal({ grps: [ 'owner-bar-a' ], 'usr$': 'derek', 'org$': 'greens' })

              derek.act(
                'role:allow,upon:grp,op:add,tgrp:write,tusr:eoin,torg:greens',
                function(err, out) {
                  expect(err.code).equal('no_in_access')

                  derek.act(
                    'role:allow,upon:grp,op:add,'+
                      'tgrp:write-bar-a,tusr:eoin,torg:greens',
                    function(err, out) {
                      expect(out).equal({ grps: [ 'write-bar-a' ],
                                          'usr$': 'eoin', 'org$': 'greens' })

                      eoin.make$('bar',{id$:1,mark:'a'}).save$(function(err, out) {
                        expect(out.mark).equal('a')

                        eoin.make$('bar',{id$:2,mark:'b'}).save$(function(err, out) {
                          expect(err.code).equal('no_write_access')

                          //console.dir(alice.export('allow').store().data(),{depth:null})
                          fin()
                        })
                      })
                    })
                })
            })
        })
      }
    })
})


function p(o) {
  console.dir(o,{depth:null,colors:true})
}

function d(s) {
  return s.export('allow').store().data()
}
