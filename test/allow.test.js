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


lab.test('validate', PluginValidator(Plugin, module))


// NEXT: validate lists


lab.test('happy', fin => {
  const kv = make_kv({
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
  })

  Seneca()
    .test('silent')
    //.test('print')
    .use('entity')
    .use(Plugin, {
      server: true,
      kv: kv
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


lab.test('org-admin', fin => {
  const kv = make_kv({
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
  })

  Seneca()
    .test('silent')
    //.test('print')
    .use('entity')
    .use(Plugin, {
      server: true,
      kv: kv
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


const kv_alice_bob_org0 = make_kv({
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
})


lab.test('resolve_perms', fin => {

  Seneca()
    .test(fin)
    .use('entity')
    .use(Plugin, {
      server: true,
      kv: kv_alice_bob_org0
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
      kv: kv_alice_bob_org0
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

  const kv_alice_bob_org1 = make_kv({
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
  })


  
  Seneca()
    //.test('print')
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      kv: kv_alice_bob_org1
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

  const kv_alice_bob_org2 = make_kv({
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
  })


  
  Seneca()
    //.test('print')
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      kv: kv_alice_bob_org2
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

  const kv_org3 = make_kv({
    'alice': {usr$:'alice', perms: [{p:{usr$:'alice',usr:'alice'}, v:true}]},
    'bob': {usr$:'bob', perms: [{p:{usr$:'bob',usr:'bob'}, v:true}]},
    
    // This is an important default, forces perms into groups
    'org3': {org$:'org3', perms: [{p:{org$:'org3'}, v:false}]},

    // the admin pseudo-group for org2
    'canfoo': {grp:'canfoo', perms: [
      {p:{role:'bar',cmd:'foo'}, v:true},
    ]},
    
    'alice~org3':{usr$:'alice', org$:'org3', grps: ['canfoo']}
  })


  
  Seneca()
    //.test('print')
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      kv: kv_org3,
      pins:[
        {role:'bar',cmd:'foo',
         make_activity$:function(activity){return activity}}
      ]
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
  
  const opts = {
    kv: make_kv(permspecs)
  }

  Plugin.intern.get_perms(opts,{usr:'alice'},function(err,out){
    if(err) return fin(err)
    expect(out.perms[0].p.usr$).equal('alice')

    Plugin.intern.get_perms(opts,{usr:'bob', org:'aaa'},function(err,out){
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


lab.test('intern-make_key', fin => {
  // NOTE: this are all IDs, not names
  expect(Plugin.intern.make_key({},{usr:'a'})).equals('a')
  expect(Plugin.intern.make_key({},{org:'b'})).equals('b')
  expect(Plugin.intern.make_key({},{usr:'x',org:'y'})).equals('x~y')
  expect(function(){Plugin.intern.make_key({},{})}).throws()
  expect(Plugin.intern.make_key({},{grp:'g'})).equals('g')
  fin()
})


lab.test('intern-grp', fin => {
  const opts = {kv:make_kv({
    'alice~reds': {usr$:'alice', org$:'reds', grps:['']}
  })}

  Plugin.intern.get_grps(opts, {usr:'alice', org:'reds'}, function(err, out) {
    if(err) return fin(err)
    expect(out).equal({ usr: 'alice', org: 'reds', grps: [ '' ] })

    Plugin.intern.grp_update(
      opts, {op:'add',usr:'alice', org:'reds', grp:'g0'},
      function(err, out) {
        if(err) return fin(err)
        expect(out).equal({ grps: [ 'g0' ], 'usr$': 'alice', 'org$': 'reds' })
        fin()
      })
  })


})

/*
lab.test('intern-set_perms', fin => {
  Plugin.intern.set_perms({kv:{set:function(k,v,r) {
    expect(k).equal('foo')
    expect(v).equal({p:{usr:'foo',usr$:'foo'},v:true})
    r()
  }}}, {usr:'foo', perms:{p:{usr:'foo',usr$:'foo'},v:true}}, next0)

  function next0() {
    Plugin.intern.set_perms({kv:{set:function(k,v,r) {
      expect(k).equal('foo~bar')
      expect(v).equal({p:{a:1},v:true})
      r()
    }}}, {usr:'foo', org:'bar', perms:{p:{a:1},v:true}}, fin)
  }
})
*/

// TODO: move internal to plugin to provide default in-memory implementation
function make_kv(permspecs) {
  return {
    get: function(key, done) {
      return setImmediate(function(){
        done(null, _.clone(permspecs[key]))
      })
    },

    sadd: function(key, prop, val, annot, done) {
      var obj = permspecs[key]

      if(!obj) {
        obj = permspecs[key] = {}
        permspecs[key][prop] = []
      }

      Object.assign(obj,annot)
      
      var set = obj[prop]
      for(var i = 0; i < set.length; i++) {
        if(val === set[i]) break;
      }

      if(i === set.length) {
        set.push(val)
      }

      done(null, obj)
    }
  }
}

