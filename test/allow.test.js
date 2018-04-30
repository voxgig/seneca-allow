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


lab.test('happy', fin => {
  const kv = make_kv({
    'aaa': {
      perms: [
        {p:{user:'aaa'}, v:true},
      ]
    },
    'bbb': {
      perms: [
        {p:{user:'bbb'}, v:true},
      ]
    },
  })

  Seneca()
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      kv: kv
    })
    .ready(function() {
      var aaa = this.delegate({user:'aaa'})
      var bbb = this.delegate({user:'bbb'})

      aaa
        .make$('foo', {id$:1, mark:'a', user:'aaa'})
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


lab.test('org-basic', fin => {
  const kv = make_kv({
    'ccc': {
      perms: [
        {p:{user:'ccc'}, v:true},
        {p:{org:'QQQ'}, v:true},
      ]
    },
    'ddd': {
      perms: [
        {p:{user:'ddd'}, v:true},
        {p:{org:'QQQ'}, v:true},
      ]
    },
  })

  Seneca()
    .test('silent')
    .use('entity')
    .use(Plugin, {
      server: true,
      kv: kv
    })
    .ready(function() {
      var ccc = this.delegate({user:'ccc', org:'QQQ'})
      var ddd = this.delegate({user:'ddd', org:'QQQ'})

      ccc
        .make$('bar', {id$:1, mark:'b', user:'ccc', org:'QQQ'})
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


lab.test('intern-get_perms', fin => {
  const permspecs = {
    alice: {perms:[{p:{usr:'alice'},v:true}]},
    bob: {usr:'',perms:[{p:{usr:'bob'},v:true}]},
    'bob~aaa': {org:'aaa',groups:['g0']},
    'g0': {name:'g0',org:'aaa',perms:[{p:{color:'red'},v:true}]},
  }
  
  const opts = {
    fields:{usr:'usr', org:'org'},
    kv: make_kv(permspecs)
  }

  Plugin.intern.get_perms(opts,{usr:'alice'},function(err,out){
    //console.log('GP alice',err)
    //console.dir(out,{depth:null,colors:true})
    expect(out.perms[0].p.usr).equal('alice')
    
    Plugin.intern.get_perms(opts,{usr:'bob', org:'aaa'},function(err,out){
      //console.log('GP bob',err)
      //console.dir(out,{depth:null,colors:true})
      expect(out.perms[0].p.usr).equal('bob')
      expect(out.perms[1].p).equal({ color: 'red', org: 'aaa' })
      
      fin()
    })
  })
})


function make_kv(permspecs) {
  return {
    get: function(key, done) {
      return done(null, _.clone(permspecs[key]))
    }
  }
}

