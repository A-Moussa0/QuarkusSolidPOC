const http = require('http');

const port = 8080;
const headers = {
    'Access-Control-Allow-Origin': '*', /* @dev First, read about security */
    'Access-Control-Allow-Methods': 'OPTIONS, POST, GET, DELETE, PUT',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Max-Age': 2592000 // 30 days
    /** add other headers as per requirement */
};

const requestListener = function (req, res) {
    console.log(req.method, req.url);
    if (req.method === 'OPTIONS') {
        res.writeHead(204, headers);
        res.end();
        return;
    }

    if (req.method === 'PUT') {
        headers['Content-Type'] = 'application/json';
        res.writeHead(200, headers);
        res.end(JSON.stringify({ message: 'User updated successfully'}));
        return;
    }

    if (req.method === 'DELETE') {
        headers['Content-Type'] = 'application/json';
        res.writeHead(200, headers);
        res.end(JSON.stringify({ message: 'User deleted successfully'}));
        return;
    }

    if (req.method === 'POST') {
        const token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc3Y2MwZWY0YzcxODFjZjRjMGRjZWY3YjYwYWUyOGNjOTAyMmM3NmIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJuYmYiOjE2Njc0OTI4NjMsImF1ZCI6Ijg0NDMwMTk5NDI1MC12aW82aWdybDlkajFzcWpjbjFncHVjN3BkY2lidnFvMi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjExNTYxODAyOTM4OTE1ODQ0MDI1NCIsImVtYWlsIjoiYnVzaW5lc3MxMjMyQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhenAiOiI4NDQzMDE5OTQyNTAtdmlvNmlncmw5ZGoxc3FqY24xZ3B1YzdwZGNpYnZxbzIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJuYW1lIjoiSWIgUmFtenkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUxtNXd1M2dmcGRCZk1oS0RnZm16d3FCUzEzZFpFX3V0cC1CVDlCNlF0dDQ9czk2LWMiLCJnaXZlbl9uYW1lIjoiSWIiLCJmYW1pbHlfbmFtZSI6IlJhbXp5IiwiaWF0IjoxNjY3NDkzMTYzLCJleHAiOjE2Njc0OTY3NjMsImp0aSI6IjRhNzRiN2M0YWZmYmU2MzQ4YWEwOGM1M2E1ZDhjZjE0ZTMxM2ZkNDkifQ.XZNI9bPw6Oriuqpdt85aJQzklXr0AWMltgaAKJVN0awW_jQSPYHNCeRWCEIndjiWEMYEtGCJx-ynje69JPLRuyWMr0JaDgkm-5AqsJuU30GU0Ih1e1wILDG_5nAYsPolwFoedELqFjnwCNFwEhv61AuUfQTiyEPXQiO5o7m3mFyy6FdOXx6Ik10s9VGDybwJJAvfZJta5tV1RRWiv6i__-0BlMNl34iHZRabe7Ep3f5veH5JT8Qe0kKPUCEID0FJBDa-rSsK6kSKUjjBKN_r3uIfcYPM-plfW_1nf6Oni0YNHHiI1da0DFCon8Zm2vcMro7SKj_vVLFu2RbAiWWhOw';
        if (req.url === '/users') {
            headers['Content-Type'] = 'application/json';
            res.writeHead(200, headers);
            res.end('User created successfully');
            return;
        }

        if (req.url === '/login') {
            headers['Content-Type'] = 'application/json';
            res.writeHead(200, headers);
            res.end(JSON.stringify({ token, username: 'Ibrahim' }));
            return;
        }

        if (req.url === '/signup') {
            headers['Content-Type'] = 'application/json';
            res.writeHead(200, headers);
            res.end(JSON.stringify({ token, username: 'Ibrahim' }));
            return;
        }
    }

    if (['GET'].indexOf(req.method) > -1) {
        if (req.url === '/users') {
            headers['Content-Type'] = 'application/json';
            res.writeHead(200, headers);
            res.end(JSON.stringify({
                users: [
                    {
                        id: 1, username: 'ibrahim', first_name: 'ibrahim', last_name: "", email: 'email@gmail.com', phone_number: "01024121213", zip_code: "12345"
                    },
                    {
                        id: 2, username: 'mohamed', first_name: 'mohamed', last_name: "", email: 'email1@gmail.com', phone_number: "01124121213", zip_code: "12345"
                    },
                    {
                        id: 3, username: 'ahmed', first_name: 'ahmed', last_name: "", email: 'email2@gmail.com', phone_number: "01224121213", zip_code: "12345"
                    }
                ]
            }));
            return;
        }

        res.writeHead(200, headers);
        res.end('Hello World');
        return;
    }

    res.writeHead(405, headers);
    res.end(`${req.method} is not allowed for the request.`);
    return;
}

const server = http.createServer(requestListener);
server.listen(port);