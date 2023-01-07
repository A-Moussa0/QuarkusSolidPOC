import { logout } from './Auth';

const makeRequest = async (req: Promise<Response>) => {
    const res = await req
    
    if (res.status === 200) {
        const data = await res.json();
        return { status: 200, data: data };
    }
    if (res.status === 400) {
        const data = await res.json();
        return { status: res.status, errors: data.violations }
    }
    
    if (res.status === 401) logout()

    return { status: res.status, errors: [] }
}

export { makeRequest }