import { createServer } from 'net';
const server = createServer();
server.listen(0, '0.0.0.0', () => {
    const addr = server.address();
    console.log(`bound=${addr.address}:${addr.port}`);
    server.close();
});
