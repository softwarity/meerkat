// Minimal SMTP sink for the integration suite: accepts everything on :12525
// and writes each message as JSON into .tmp/mail/ — the self-registration
// test reads the confirmation link back from there. No dependency, no TLS.
import { createServer } from 'node:net';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const PORT = 12525;
const DIR = fileURLToPath(new URL('../.tmp/mail', import.meta.url));
mkdirSync(DIR, { recursive: true });

let counter = 0;

createServer((socket) => {
  let buffer = '';
  let inData = false;
  let mail = { from: '', to: [], data: '' };
  const reply = (s) => socket.write(s + '\r\n');
  reply('220 smtp-sink ready');

  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    for (;;) {
      if (inData) {
        const end = buffer.indexOf('\r\n.\r\n');
        if (end < 0) return;
        mail.data = buffer.slice(0, end);
        buffer = buffer.slice(end + 5);
        inData = false;
        const file = `${DIR}/${Date.now()}-${counter++}.json`;
        writeFileSync(file, JSON.stringify(mail, null, 2));
        console.log(`[smtp-sink] ${mail.to.join(', ')} -> ${file}`);
        mail = { from: '', to: [], data: '' };
        reply('250 OK stored');
        continue;
      }
      const nl = buffer.indexOf('\r\n');
      if (nl < 0) return;
      const line = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 2);
      const cmd = line.toUpperCase();
      if (cmd.startsWith('EHLO') || cmd.startsWith('HELO')) reply('250 smtp-sink');
      else if (cmd.startsWith('MAIL FROM:')) {
        mail.from = line.slice(10).trim();
        reply('250 OK');
      } else if (cmd.startsWith('RCPT TO:')) {
        mail.to.push(line.slice(8).trim().replace(/^<|>$/g, ''));
        reply('250 OK');
      } else if (cmd.startsWith('DATA')) {
        inData = true;
        reply('354 go ahead');
      } else if (cmd.startsWith('QUIT')) {
        reply('221 bye');
        socket.end();
      } else reply('250 OK');
    }
  });
  socket.on('error', () => {});
}).listen(PORT, () => console.log(`smtp-sink on :${PORT}, mail dir ${DIR}`));
