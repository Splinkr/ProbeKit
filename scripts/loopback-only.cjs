'use strict'

// A distribuicao oficial chama listen(port) e aceita todas as interfaces.
// Este preloader limita os sockets TCP do laboratorio ao loopback.
const net = require('node:net')
const originalListen = net.Server.prototype.listen

net.Server.prototype.listen = function (...args) {
  if (typeof args[0] === 'object' && args[0] !== null) {
    args[0] = { ...args[0], host: '127.0.0.1' }
  } else if (typeof args[0] === 'number' || /^\d+$/.test(args[0])) {
    if (typeof args[1] === 'string') {
      args[1] = '127.0.0.1'
    } else {
      args.splice(1, 0, '127.0.0.1')
    }
  }
  return originalListen.apply(this, args)
}
