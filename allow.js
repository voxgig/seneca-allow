/* Copyright (c) 2018 voxgig and other contributors, MIT License */
'use strict'

// NOTE: philosophically, denied permissions are errors, as the UI should
// not enable the user to attempt disallowed operations.


// NEXT: need to maintain lists of users in groups etc, and patterns to read this
// NEXT: LRU, timeout cache, and clearance events


const Optioner = require('optioner')
const Patrun = require('patrun')
const Eraro = require('eraro')
const Jsonic = require('jsonic')

const Joi = Optioner.Joi

var Errors = require('./lib/errors')
var Store = require('./lib/store')

const optioner = Optioner({
  client: true,
  server: false,
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
  // const perms_cache = {}

  var store = Store({tag:'mem',permspecs:opts.permspecs})
  
  if(opts.server) {
    seneca.add('role:allow,get:perms', get_perms)
    seneca.add('role:allow,get:grps', get_grps)
    seneca.add('role:allow,upon:perm,op:*', perm_update)
    seneca.add('role:allow,upon:grp,op:*', grp_update)
  }
  
  function get_perms(msg, reply) {
    return intern.get_perms(store, msg, reply)
  }

  function get_grps(msg, reply) {
    return intern.get_grps(store, msg, reply)
  }

  // TODO: this needs a perm check!
  function perm_update(msg, reply) {
    return intern.perm_update(store, msg, reply)
  }

  // TODO: this needs a perm check!
  function grp_update(msg, reply) {
    return intern.grp_update(store, msg, reply)
  }

  
  // TODO: seneca.inward would be a better way to do this as guarantees coverage
  // of all role:entity actions, including those added later
  seneca.wrap('role:entity', allow_entity)


  if(opts.pins || opts.pin) {
    // TODO fix this
    var pins = opts.pins //|| Array.isArray(opts.pin) ? opts.pin : [opts.pin]
    pins.forEach(function(pin) {
      seneca.wrap(seneca.util.clean(pin),
                  make_allow_msg( pin.make_activity$ ||
                                  function(activity){return activity}))
    })
  }
  
  
  // Generic access control for any msg pattern
  function make_allow_msg(make_activity) {
    return function allow_msg(msg, reply, meta) {
      if(!msg.usr) return reply(error('no_user',{msg:msg}))

      var activity, access

      resolve_perms(this, {usr: msg.usr, org: msg.org}, function(err, perms) {
        if(err) return reply(err)

        //console.log('AM perms', perms)
        
        activity = intern.extract_pattern_values(meta)
        activity.usr$ = msg.usr
        activity.org$ = msg.org

        activity = make_activity(activity, 'in', msg, null, meta)
        //console.log('AM activity', activity)

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

        // NOTE: access does not need to be a boolean!
        // Functionality could be extended here.
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
    const key = intern.make_perms_key(context)
    var found
    
    // TODO: only use cache when you can clear it!
    //var found = perms_cache[key]
    //if(found) return done.call(seneca, null, found)

    // TODO: seneca feature: death tolerance, die after x many failed msgs
    seneca.act('role:allow,get:perms', context, function(err, permspec) {
      if(err) return done.call(this, err)

      //found = perms_cache[key] = intern.make_perms(context, permspec)
      found = intern.make_perms(context, permspec)
      return done.call(seneca, null, found)
    })
  }


  return {
    export: {
      resolve_perms: resolve_perms,

      // TODO: seneca plugin lifecycle does not support post init action hooks
      store: function(set_store) {
        return store = (set_store ? set_store : store)
      }
    }
  }
}

const intern = (module.exports.intern = {
  make_perms_key: function(context) {
    const usr = context.usr
    const org = context.org
    const grp = context.grp

    const key =
          null!=grp ? grp :
          ((null==usr?'':usr)+
           (null!=usr&&null!=org?'~':'')+
           (null==org?'':org))

    if('' === key) {
      throw error('no_key_in_context',{context:context})
    }
    
    return key
  },

  make_grps_key: function(context) {
    var usr = context.usr
    var org = context.org

    usr = '' === usr ? null : usr
    org = '' === org ? null : org
    
    if(null == usr || null == org) {
      throw error('non_empty_usr_org_required',{context:context})
    }
    
    return usr+'~'+org
  },


  get_grps: function (store, msg, reply) {
    const key = intern.make_grps_key(msg)
    store.get(key, function(err, out) {
      if(err) return reply(err)
      const grps = out && out.grps
      reply(null, {usr:msg.usr, org:msg.org, grps: grps})
    })
  },

                
  get_perms: function (store, msg, reply) {
    // These are identifiers, not string names
    const usr = msg.usr
    const org = msg.org

    var perms = []
    var waiting = 0
    
    // user's groups in this org
    store.get(usr+'~'+org, function(err, out) {
      if(err) return reply(err)

      if(out && out.grps) {
        out.grps.forEach(function(grp) {
          store.get(grp, addperm(grp,{usr$:usr,org$:org})) // org's perms
        })
      }
    }) 
    
    store.get(usr, addperm('usr')) // user's perms
    store.get(org, addperm('org'),{usr$:usr}) // org's perms

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

  perm_update: function (store, msg, reply) {
    const ops = {add:'add', rem:'rem'}
    const op = ops[msg.op]
    const perm = msg.perm
    
    if(null == op) return reply()

    if(null != perm) {
      if(null == perm.p || null == perm.v) {
        throw error('invalid_perm',{perm:perm})
      }
    }

    const annot = {}
    if(null != msg.tusr) annot.usr$ = msg.tusr
    if(null != msg.torg) annot.org$ = msg.torg
    if(null != msg.tgrp) annot.grp$ = msg.tgrp

    const key = intern.make_perms_key({
      usr: msg.tusr, org: msg.torg, grp: msg.tgrp
    })

    //delete perms_cache[key]    
    
    if('add' === op) {
      store.sadd(
        key,
        'perms',
        perm,
        annot,
        function(err, out) {
          if(err) return reply(err)
          reply(null, out)
        })
    }
    else if('rem' === op) {
      store.srem(
        key,
        'perms',
        perm,
        annot,
        function(err, out) {
          if(err) return reply(err)
          reply(null, out)
        })
    }
    else {
      reply()
    }
  },

  grp_update: function (store, msg, reply) {
    const ops = {add:'add', rem:'rem'}
    const op = ops[msg.op]
    const tgrp = msg.tgrp
    const key = intern.make_grps_key({usr: msg.tusr, org: msg.torg})

    if(null == op) return reply()

    if(null == tgrp || '' == tgrp) {
      throw error('invalid_perm',{perm:perm})
    }

    if('add' === op) {
      store.sadd(
        key,
        'grps',
        tgrp,
        {usr$:msg.tusr,org$:msg.torg},
        function(err, out) {
          if(err) return reply(err)
          reply(null, out)
        })
    }
    else if('rem' === op) {
      store.srem(
        key,
        'grps',
        tgrp,
        {usr$:msg.tusr,org$:msg.torg},
        function(err, out) {
          if(err) return reply(err)
          reply(null, out)
        })
    }
    else {
      return reply()
    }
  },


  init_perms: function() {
    // TODO: init perms for usr or org
  },
  
  
  make_perms: function (context, permspec) {
    const perms = Patrun({gex: true})
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
