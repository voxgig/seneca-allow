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
        .save$(function (err, foo) {
          if(err) return fin(err)
          expect(foo.mark).equal('a')
          
          aaa
            .make$('foo')
            .load$(1,function (err, foo2) {
              expect(foo2.mark).equal('a')
              expect(foo2.id).equal(foo.id)
              
              bbb
                .make$('foo')
                .load$(1,function (err, foo) {
                  expect(err).exist()
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
    {p:{cmd$:'load'}, v:true}
  ]},
  
  'alice~org0':{usr$:'alice', org$:'org0', groups: ['admin0']},
  'bob~org0':{usr$:'bob', org$:'org0', groups: ['read0']},
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
              expect(out.find({usr$:'bob',org$:'org0',cmd$:'load'})).equal(true)
              expect(out.find({usr$:'bob',org$:'org0',cmd$:'save'})).equal(false)

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
              expect(err).exist()
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
      {p:{cmd$:'load',mark:'a'}, v:true}
    ]},
    
    'alice~org1':{usr$:'alice', org$:'org1', groups: ['admin0']},
    'bob~org1':{usr$:'bob', org$:'org1', groups: ['read1']},
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
            expect(err).exist()
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
                    expect(err).exist()
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


lab.test('intern-get_perms', fin => {
  const permspecs = {
    alice: {perms:[{p:{usr$:'alice'},v:true}]},

    'aaa': {org$:'aaa',perms:[{p:{org$:'aaa'},v:false}]},
    'g0': {grp:'g0',org$:'aaa',perms:[{p:{color:'red'},v:true}]},
    
    bob: {usr$:'bob',perms:[{p:{usr$:'bob'},v:true}]},
    'bob~aaa': {usr$:'bob',org$:'aaa',groups:['g0']},

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


function make_kv(permspecs) {
  return {
    get: function(key, done) {
      return setImmediate(function(){
        done(null, _.clone(permspecs[key]))
      })
    }
  }
}

