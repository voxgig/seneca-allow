/* Copyright (c) 2018 voxgig and other contributors, MIT License */
'use strict'

const Optioner = require('optioner')
const Patrun = require('patrun')

const Joi = Optioner.Joi

const optioner = Optioner({
  kv: Joi.object().required()
})

module.exports = function allow(options) {
  const seneca = this
  const opts = optioner.check(options)

  // TODO: just a cache, should be time limited
  // and accept inbound msgs to update if changes made to stored perms
  const perms = {}

  const kv = options.kv

  seneca.add('role:allow,get:perms', get_perms)

  
  function get_perms(msg, reply) {
    // TODO: key by user and org, intent is to load
    // org groups and merge into single perm patrun
    const key = msg.user
    kv.get(key, function (err, permspec) {
      reply(err || permspec)
    })
  }
  
  
  // TODO: seneca.inward would be a better way to do this as guarantees coverage
  // of all role:entity actions
  seneca.wrap('role:entity', allow)

  
  function allow(msg, reply) {
    if(!msg.user) return reply(new Error('no-context'))

    resolve_perms(this, {user: msg.user}, function(err, perms) {
      if(err) return reply(err)
      var activity

      // case: write operation, ent given
      if('save' === msg.cmd || 'remove' === msg.cmd ) {
        activity = intern.make_activity(msg, msg.ent)
        console.log('before activity', activity)
      
        const access = perms.find(activity)
        console.log('BEFORE', access, activity, perms)

        if(!access) {
          return reply(new Error('no-access'))
        }

        return this.prior(msg, reply)
      }

      // case: read operation, ent returned
      else {
        return this.prior(msg, function(err, out) {
          if(err) return reply(err)

          // TODO: is this correct? is this leaking info - should we instead
          // send an explicit not-allowed? it is not-allowed?
          if(!out) return reply()
          
          activity = intern.make_activity(msg, out)
          console.log('after activity', activity)
      
          // TODO: handle result sets with lists of ents
          const access = perms.find(activity)

          console.log('AFTER', access, activity, perms)
          if(!access) {
            return reply(new Error('no-access'))
          }

          return reply(null, out)
        })
      }
    })
  }


  function resolve_perms(seneca, context, done) {
    var found = perms[context.user]

    if(found) return done.call(seneca, null, found)

    seneca.act('role:allow,get:perms', context, function(err, permspec) {
      if(err) return done.call(this, err)

      if(permspec) {
        found = perms[context.user] = intern.make_perms(context, permspec)
      }

      return done.call(seneca, null, found)
    })
  }
}

const intern = (module.exports.intern = {
  make_perms: function make_perms(context, permspec) {
    const perms = Patrun()
    permspec.perms.forEach(function(perm) {
      perms.add(perm.p,perm.v)
    })
    console.log('make_perms',context, perms)
    return perms
  },

  make_activity: function make_activity(msg, ent) {
    const activity = ent.data$()

    var canon = msg.ent.canon$({object:true})
    
    activity.user$ = msg.user
    activity.org$ = msg.org
    activity.zone$ = canon.zone
    activity.base$ = canon.base
    activity.name$ = canon.name
    activity.cmd$ = msg.cmd

    return activity
  }
})
