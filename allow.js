/* Copyright (c) 2018 voxgig and other contributors, MIT License */
'use strict'

// NEXT: verify network lookup
// NEXT: LRU, timeout cache


const Optioner = require('optioner')
const Patrun = require('patrun')
const Eraro = require('eraro')
const Jsonic = require('jsonic')

const Joi = Optioner.Joi

var Errors = require('./lib/errors')

const optioner = Optioner({
  client: true,
  server: false,
  kv: Joi.object({
    get: Joi.func(),
    set: Joi.func()
  }),
})

var error = exports.error = Eraro({
  package: 'seneca',
  msgmap: Errors,
  override: true
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
    // TODO: this needs a perm check!
    return intern.set_perms(opts, msg, reply)
  }

  
  // TODO: seneca.inward would be a better way to do this as guarantees coverage
  // of all role:entity actions, including those added later
  seneca.wrap('role:entity', allow_entity)


  if(opts.pins || opts.pin) {
    var pins = opts.pins //|| Array.isArray(opts.pin) ? opts.pin : [opts.pin]
    pins.forEach(function(pin) {
      seneca.wrap(seneca.util.clean(pin), make_allow_msg(pin.make_activity$))
    })
  }
  
  
  // Generic access control for any msg pattern
  function make_allow_msg(make_activity) {
    return function allow_msg(msg, reply, meta) {
      if(!msg.usr) return reply(error('no_user',{msg:msg}))

      var activity, access

      resolve_perms(this, {usr: msg.usr, org: msg.org}, function(err, perms) {
        if(err) return reply(err)

        activity = intern.extract_pattern_values(meta)
        activity.usr$ = msg.usr
        activity.org$ = msg.org

        activity = make_activity(activity, 'in', msg, null, meta)
        if(activity) {
          access = perms.find(activity)

          if(!access) {
            return reply(error('no_in_access',{activity:activity}))
          }
        }

        return this.prior(msg, function(err, out, meta) {
          activity = intern.extract_pattern_values(meta)
          activity.usr$ = msg.usr
          activity.org$ = msg.org

          activity = make_activity(activity, 'out', msg, out, meta)
          if(activity) {
            access = perms.find(activity)
            if(!access) {
              return reply(error('no_out_access',{activity:activity}))
            }
          }

          return reply(err, out)
        })
      })
    }
  }
  
  
  function allow_entity(msg, reply) {
    if(!msg.usr) return reply(error('no_user',{msg:msg}))

    resolve_perms(this, {usr: msg.usr, org: msg.org}, function(err, perms) {
      if(err) return reply(err)
      var activity

      // case: write operation, ent given
      if('save' === msg.cmd || 'remove' === msg.cmd ) {
        activity = intern.make_entity_activity(msg, msg.ent)
        
        const access = perms.find(activity)

        if(!access) {
          return reply(error('no_write_access',{activity:activity}))
        }

        return this.prior(msg, reply)
      }

      // case: read operation, ent returned
      else if('load' === msg.cmd) {
        return this.prior(msg, function(err, out, meta) {
          if(err) return reply(err)

          // TODO: is this correct? is this leaking info - should we instead
          // send an explicit not-allowed? it is not-allowed?
          if(!out) return reply()
          
          activity = intern.make_entity_activity(msg, out)

          const access = perms.find(activity)

          if(!access) {
            return reply(error('no_read_access',{activity:activity}))
          }

          return reply(out)
        })
      }

      // case: list operation, ent returned
      else if('list' === msg.cmd) {

        // TODO: pull out fields to use in query, as optimization
        return this.prior(msg, function(err, reslist, meta) {
          if(err) return reply(err)

          if(!reslist) return reply()

          var list = []

          reslist.forEach(function(ent){
            activity = intern.make_entity_activity(msg, ent)
            var access = perms.find(activity)
            
            if(access) {
              list.push(ent)
            }
          })

          return reply(list)
        })
      }
      else {
        // better to return no data
        reply()
      }
    })
  }


  function resolve_perms(seneca, context, done) {
    const key = intern.make_key(opts, context)
    var found = perms[key]

    if(found) return done.call(seneca, null, found)

    // TODO: seneca feature: death tolerance, die after x many failed msgs
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
    const key =
          (null==usr?'':usr)+
          (null!=usr&&null!=org?'~':'')+
          (null==org?'':org)

    if('' === key) {
      throw error('no_key_in_context',{context:context})
    }
    
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

  // TODO: incorrect: set ops should be set_group, add/rem user from group
  // TODO: this needs protection
  set_perms: function (opts, msg, reply) {
    const key = intern.make_key(opts, msg)
    opts.kv.set(key, msg.perms, function() {
      reply()
    })
  },


  init_perms: function() {
    // TODO: init perms for usr or org
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

  make_entity_activity: function (msg, ent) {
    const activity = ent.data$()

    var canon = msg.ent.canon$({object:true})

    activity.ent$ = true
    activity.usr$ = msg.usr
    activity.org$ = msg.org
    activity.zone$ = canon.zone
    activity.base$ = canon.base
    activity.name$ = canon.name
    activity.cmd$ = msg.cmd

    return activity
  },


  extract_pattern_values: function(meta) {
    return Jsonic(meta.pattern)
  }
})
