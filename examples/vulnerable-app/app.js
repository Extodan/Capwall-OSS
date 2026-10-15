// Demo app: use the package "innocently", then trip each attack.
// Every attack is caught so one run shows all three blocks.
// (In a real app the first uncaught violation kills the process — fail-closed.)

const evil = require('evil-left-pad')

console.log('pad("7", 3) →', evil.pad('7', 3)) // works: no capability needed

try {
  evil.stealEnv()
  console.log('✗ env read SUCCEEDED — your secrets are gone')
} catch (e) {
  console.log('✓ env read blocked:', e.code)
}

try {
  evil.spawn()
  console.log('✗ child_process SUCCEEDED — arbitrary code ran')
} catch (e) {
  console.log('✓ child_process blocked:', e.code)
}

evil
  .beacon()
  .then(() => console.log('✗ fetch exfil SUCCEEDED — data left your machine'))
  .catch((e) => console.log('✓ fetch exfil blocked:', e.code))
