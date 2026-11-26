import { createHash, randomBytes } from 'node:crypto';

// Gera um token de acesso para o app e o hash que deve ser configurado no servidor.
// Somente o hash fica no servidor; o token é digitado uma vez no app (Configurações).
const token = randomBytes(32).toString('base64url');
const hash = createHash('sha256').update(token).digest('hex');

console.log('Token para o app (guarde com segurança, não será exibido de novo):');
console.log(`  ${token}`);
console.log('\nAdicione ao servidor:');
console.log(`  AEGIS_CLIENT_TOKEN_HASHES=${hash}`);
