/* Copyright (c) 2018 voxgig and other contributors, MIT License */
'use strict'

const Optioner = require('optioner')
const Patrun = require('patrun')

const Joi = Optioner.Joi

const optioner = Optioner({
  client: true,
  server: false,
  kv: Joi.object(),

  // TODO: nope, just fix as 'usr', 'org'
  fields: {
    usr: 'user',
    org: 'org',
  }
})

module.exports = function allow(options) {
  const seneca = this
  const opts = optioner.check(options)

  const usr_field = opts.fields.usr
  const org_field = opts.fields.org
  
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
  seneca.wrap('role:entity', allow)

  
  function allow(msg, reply) {
    if(!msg[usr_field]) return reply(new Error('no-context'))

    resolve_perms(this, {user: msg[usr_field]}, function(err, perms) {
      if(err) return reply(err)
      var activity

      // case: write operation, ent given
      if('save' === msg.cmd || 'remove' === msg.cmd ) {
        activity = intern.make_activity(msg, msg.ent)
      
        const access = perms.find(activity)

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
      
          // TODO: handle result sets with lists of ents
          const access = perms.find(activity)

          if(!access) {
            return reply(new Error('no-access'))
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

      if(permspec) {
        found = perms[key] = intern.make_perms(context, permspec)
      }

      return done.call(seneca, null, found)
    })
  }
}

const intern = (module.exports.intern = {
  make_key: function(opts, context) {
    const usr = context[opts.fields.usr]
    const org = context[opts.fields.org]
    const key = usr+(null==org?'':'~'+org)
    return key
  },

  get_perms: function (opts, msg, reply) {
    // TODO: these are identifiers, not string names
    const usr = msg[opts.fields.usr]
    const org = msg[opts.fields.org]

    const tmp = {}
    tmp.grp = []
    tmp.num_grps = 0
    tmp.has_grps = true
    
    // Get the user's permspec
    opts.kv.get(usr, function (err, usr_permspec) {
      tmp.err = err
      if(err || null == usr_permspec) return finish()
      
      tmp.usr = usr_permspec.perms
      finish()
    })

    if(null == msg.org) {
      tmp.has_grps = false
      finish()
    }
    else {
      // Get the groups (as ids) in this org that the user is in
      const usr_org = intern.make_key(opts, msg)
      opts.kv.get(usr_org, function (err, grp_set) {
        tmp.err = err
        if(err || null == grp_set || null == grp_set.groups) {
          tmp.has_grps = false
          return finish()
        }
        
        tmp.num_grps = grp_set.groups.length
        tmp.has_grps = 0 < tmp.num_grps
        
        for(var i = 0; i < tmp.num_grps; i++) {
          var grp_id = grp_set.groups[i]
          opts.kv.get(grp_id, function(err, grp_permspec) {
            tmp.err = err
            if(err || null == grp_permspec) return finish()

            // Force inject the org to ensure perm only applies to org entities
            grp_permspec.perms.forEach(function(perms) {
              perms.p.org = org
            })
            
            tmp.grp.push(grp_permspec.perms)
            finish()
          })
        }

        finish()
      })
    }
  
    function finish() {
      if(!tmp.end) {

        if(tmp.err) {
          tmp.end = true
          return reply(tmp.err)
        }
        else if(tmp.usr &&
                (!tmp.has_grps ||
                 (0 < tmp.num_grps && (tmp.grp.length === tmp.num_grps)))) {

          const out = {
            perms: tmp.usr
          }
          
          out.usr = usr
          out.org = org
          out.perms = tmp.usr
          tmp.grp.forEach(function(g){out.perms = out.perms.concat(g)})
          
          tmp.end = true


          // TODO: and cache here too
          reply(null, out)
        }
      }
    }
  },

  // TODO: this needs protection
  set_perms: function (opts, msg, reply) {
    // TODO: set perms only for user, and org+group
    const key = msg[opts.fields.usr]
    opts.kv.set(key, msg.perms, reply)
  },

  make_perms: function (context, permspec) {
    const perms = Patrun()
    permspec.perms.forEach(function(perm) {
      perms.add(perm.p,perm.v)
    })
    return perms
  },

  make_activity: function (msg, ent) {
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
