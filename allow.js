/* Copyright (c) 2018 voxgig and other contributors, MIT License */
'use strict'

// NEXT: handle lists - loop over results - optimize later
// NEXT: verify network lookup
// NEXT: LRU, timeout cache
// NEXT: proper error codes


const Optioner = require('optioner')
const Patrun = require('patrun')

const Joi = Optioner.Joi

const optioner = Optioner({
  client: true,
  server: false,
  kv: Joi.object(),
})

module.exports = function allow(options) {
  const seneca = this
  const opts = optioner.check(options)

  // TODO: just a cache, should be time limited
  // and accept inbound msgs to update if changes made to stored perms
  const perms = {}

  const kv = options.kv

  if(opts.server) {
    seneca.add('role:allow,get:perms', get_perms)
    seneca.add('role:allow,set:perms', set_perms)
  }


  function get_perms(msg, reply) {
    return intern.get_perms(opts, msg, reply)
  }

  function set_perms(msg, reply) {
    return intern.set_perms(opts, msg, reply)
  }

  
  // TODO: seneca.inward would be a better way to do this as guarantees coverage
  // of all role:entity actions
  seneca.wrap('role:entity', allow_entity)

  
  function allow_entity(msg, reply) {
    if(!msg.usr) return reply(new Error('no-context'))

    resolve_perms(this, {usr: msg.usr, org: msg.org}, function(err, perms) {
      if(err) return reply(err)
      var activity

      // case: write operation, ent given
      if('save' === msg.cmd || 'remove' === msg.cmd ) {
        activity = intern.make_activity(msg, msg.ent)
        
        const access = perms.find(activity)

        if(!access) {
          return reply(new Error('no-write-access'))
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

          // TODO: handle result sets with lists of ents
          const access = perms.find(activity)

          //console.log(activity, perms)
          
          if(!access) {
            return reply(new Error('no-read-access'))
          }

          return reply(null, out)
        })
      }
    })
  }


  function resolve_perms(seneca, context, done) {
    const key = intern.make_key(opts, context)
    var found = perms[key]

    if(found) return done.call(seneca, null, found)

    seneca.act('role:allow,get:perms', context, function(err, permspec) {
      if(err) return done.call(this, err)

      found = perms[key] = intern.make_perms(context, permspec)
      return done.call(seneca, null, found)
    })
  }


  return {
    export: {
      resolve_perms: resolve_perms
    }
  }
}

const intern = (module.exports.intern = {
  make_key: function(opts, context) {
    const usr = context.usr
    const org = context.org
    const key = usr+(null==org?'':'~'+org)
    return key
  },

  get_perms: function (opts, msg, reply) {
    // These are identifiers, not string names
    const usr = msg.usr
    const org = msg.org

    var perms = []
    var waiting = 0
    
    // user's groups in this org
    opts.kv.get(usr+'~'+org, function(err, out) {
      if(err) return reply(err)

      if(out && out.groups) {
        out.groups.forEach(function(grp) {
          opts.kv.get(grp, addperm(grp,{usr$:usr,org$:org})) // org's perms
        })
      }
    }) 
    
    opts.kv.get(usr, addperm('usr')) // user's perms
    opts.kv.get(org, addperm('org'),{usr$:usr}) // org's perms

    function addperm(what,context) {
      waiting++
      return function(err, out) {
        if(-1 === waiting) reutrn

        if(err) {
          waiting = -1
          return reply(err)
        }

        if(out && out.perms) {
          if(context) {
            out.perms.forEach(function(perm){
              Object.keys(context).forEach(function(field){
                perm.p[field] = context[field]
              })
            })
          }
          perms = perms.concat(out.perms)
        }

        waiting--
        if(0 === waiting) {
          reply(null, {perms:perms})
        }
      }
    }    
  },

  // TODO: this needs protection
  set_perms: function (opts, msg, reply) {
    // TODO: set perms only for usr, and org+group
    const key = msg[opts.fields.usr]
    opts.kv.set(key, msg.perms, reply)
  },

  make_perms: function (context, permspec) {
    const perms = Patrun()
    if(permspec && permspec.perms) {
      permspec.perms.forEach(function(perm) {
        perms.add(perm.p,perm.v)
      })
    }
    return perms
  },

  make_activity: function (msg, ent) {
    const activity = ent.data$()

    var canon = msg.ent.canon$({object:true})
    
    activity.usr$ = msg.usr
    activity.org$ = msg.org
    activity.zone$ = canon.zone
    activity.base$ = canon.base
    activity.name$ = canon.name
    activity.cmd$ = msg.cmd

    return activity
  }
})
