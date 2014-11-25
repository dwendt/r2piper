var r2pipe = require('r2pipe'),
    _      = require('underscore');

var activePipes = [];

var r2piper = {
  init: function(cb) {
    // TODO: check if r2 is actually installed?

    cb();
  },
  // Creates a new pipe-based pipe. callback(err, pipeRef)
  add: function(ident, cb) {
    r2pipe.launch(ident, function(r2) {
      if (r2) {
        var pipeRef = activePipes.length;
        activePipes.push(r2);

        // TODO: seems after we add we should do "af" automatically

        cb(null, pipeRef);
      } else {
        cb("Failed to create pipe.");
      }
    });
  },
  // Creates a new local TCP-based pipe. callback(err, pipeRef)
  addTCP: function(ident, cb) {
  
    cb("unimpl");
  },
  // Creates a new pipe to a URL callback(err, pipeRef)
  addURL: function(ident, cb) {
  
    cb("unimpl");
  },
  // Gets a pipe safely. callback(err, pipe)
  get: function(ref, cb) {
    try {
      if (activePipes[ref] !== 0) {
        cb(null, activePipes[ref]);
      } else {
        cb("No such pipe.");
      }
    } catch (err) {
      cb("No such pipe.");
    }
  },
  // Removes a pipe.
  del: function(ref, cb) {
    try {
      activePipes[ref].quit();
      activePipes[ref] = 0;
      cb();
    } catch (err) {
      cb("No such pipe.");
    }
  },
  // Handle killing the pipes/cleanup.
  shutdown: function(cb) {
    _.each(activePipes, function(pipe) {
      pipe.quit();
    });
    cb();
  },

  // API stuff begins here. TODO: array of api funcs?

  // Uses "pD length @offset" to get disassembly with control flow
  // cb(err, String of disassembly)
  disassFormatted: function(ref, length, offset, cb) {
    var off = offset ? "@" + offset : '';

    get(ref, function(err, pipe) {
      if(err) return cb(err);

      pipe.cmd("pD " + length + off, cb);
    });
  },
  // Uses "pi @b:bytes @offset" to get disassembly without extra stuff.
  // cb(err, String of disasm)
  disass: function(ref, bytes, offset, cb) {
    var off = offset ? "@" + offset : '';

    get(ref, function(err, pipe) {
      if(err) return cb(err);

      pipe.cmd("pi @b:" + bytes + off, cb);
    });
  },
  // Uses a combo of instructions to get segment info in js obj format.
  // cb(err, object of segment inf)
  sections: function(ref, cb) {
    get(ref, function(err, pipe) {
      if(err) cb(err);

      pipe.cmdj("Sj", cb);
    });
  },
  // cb(err, obj) ex: obj.strings[0].string, type, size, length, paddr, vaddr
  strings: function(ref, cb) {
    get(ref, function(err, pipe) {
      if(err) cb(err);

      pipe.cmdj("izz", function(dat) {
        cb(dat.strings);
      });
    });
  },

  xrefs: function(ref, sym, cb) {
    get(ref, function(err, pipe) {
      if(err) cb(err);

      var search = sym; // todo: escape
      pipe.cmdj("axt @"+search, cb);
    });
  }


};

module.exports = r2piper;
