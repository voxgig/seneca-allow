/* Copyright (c) 2018 voxgig and other contributors, MIT License */
'use strict'


const _ = require('lodash')


module.exports = function mem_perm_store(opts) {
  opts = opts || {}
  const permspecs = opts.permspecs || {}
  
  return {
    tag: opts.tag,
    data: function() {
      return permspecs
    },
    
    // Get: get value of key, or null if not found
    get: function(key, done) {
      return setImmediate(function(){
        done(null, _.cloneDeep(permspecs[key]))
      })
    },

    // Set Add: maintains uniqueness in list
    sadd: function(key, prop, val, annot, done) {
      var obj = permspecs[key]

      if(!obj) {
        obj = permspecs[key] = {}
        permspecs[key][prop] = []
      }

      // self-correct usr$, org$, grp$
      Object.assign(obj,annot)

      // null vals are ignored, not errored - allows creation of empty perms
      if(null != val) {
        var set = obj[prop]
        for(var i = 0; i < set.length; i++) {
          if(intern.equal(val,set[i])) break;
        }

        if(i === set.length) {
          set.push(val)
        }
      }

      done(null, obj)
    },

    // Set Remove: idempotent
    srem: function(key, prop, val,annot, done) {
      var obj = permspecs[key]
      
      if(!obj) {
        return done()
      }

      // self-correct usr$, org$
      Object.assign(obj,annot)
      
      var set = obj[prop]
      for(var i = 0; i < set.length; i++) {
        if(intern.equal(val,set[i])) break;
      }
      
      if(i < set.length) {
        set.splice(i,1)
      }

      done(null, obj)
    }
  }
}


const intern = (module.exports.intern = {
  equal: function(a,b) {
    if('object' === typeof(a) && 'object' === typeof(b)) {
      return _.isEqual(a,b)
    }
    else {
      return a === b
    }
  }
})
