/* Copyright (c) 2018 voxgig and other contributors, MIT License */
'use strict'

const Util = require('util')

const Lab = require('lab')
const Code = require('code')
const lab = (exports.lab = Lab.script())
const expect = Code.expect

const PluginValidator = require('seneca-plugin-validator')
const Seneca = require('seneca')
const Plugin = require('..')

lab.test('validate', PluginValidator(Plugin, module))


lab.test('happy', fin => {
  const permspecs = {
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
  }

  Seneca()
    .test('print')
    .use('entity')
    .use(Plugin, {
      kv: {
        get: function(key, done) {
          return done(null, permspecs[key])
        }
      }
    })
    .ready(function() {
      console.log('ready')
      
      var aaa = this.delegate({user:'aaa'})
      var bbb = this.delegate({user:'bbb'})

      aaa
        .make$('foo', {id$:1, mark:'a', user:'aaa'})
        .save$(function (err, foo) {
          console.log('save', err, foo)
          if(err) return fin(err)
          
          aaa
            .make$('foo')
            .load$(1,function (err, foo) {
              console.log('aaa load', err, foo)
              
              bbb
                .make$('foo')
                .load$(1,function (err, foo) {
                  console.log('bbb load', err, foo)
                  fin()
                })
            })
        })
    })
})


lab.test('org-basic', fin => {
  const permspecs = {
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
  }

  Seneca()
    .test('print')
    .use('entity')
    .use(Plugin, {
      kv: {
        get: function(key, done) {
          return done(null, permspecs[key])
        }
      }
    })
    .ready(function() {
      console.log('ready')
      
      var ccc = this.delegate({user:'ccc', org:'QQQ'})
      var ddd = this.delegate({user:'ddd', org:'QQQ'})

      ccc
        .make$('bar', {id$:1, mark:'a', user:'ccc', org:'QQQ'})
        .save$(function (err, bar) {
          console.log('save', err, bar)
          if(err) return fin(err)
          
          ccc
            .make$('bar')
            .load$(1,function (err, bar) {
              console.log('ccc load', err, bar)
              
              ddd
                .make$('bar')
                .load$(1,function (err, bar) {
                  console.log('ddd load', err, bar)
                  fin()
                })
            })
        })
    })
})



