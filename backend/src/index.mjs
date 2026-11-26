import { loadConfig } from './config.mjs';
import { startServer } from './server.mjs';

let config;
try {
  config = loadConfig();
} catch (error) {
  console.error(`Configuração inválida: ${error.message}`);
  process.exit(1);
}

const server = startServer(config);
server.listen(config.port, config.host, () => {
  const scheme = config.tls ? 'https' : 'http (TLS no proxy)';
  console.log(`AEGIS backend em ${scheme}://${config.host}:${config.port} · modo ${config.mode} · uploads ${config.allowUploads ? 'ativados' : 'desativados'}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
