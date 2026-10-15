const evil = require('evil-color-logger')
console.log('app output:', evil.colorize('still works'))
setTimeout(() => process.exit(0), 800)