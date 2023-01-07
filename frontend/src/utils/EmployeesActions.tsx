import { Employee } from "../pages/inc/Types";
import { makeRequest } from "./FetchWrapper";
import { setStore, store } from "../store";

const setAlert = (message: string, isError: boolean) => {
    isError ? setStore({error: message}) : setStore({message})
}

const getEmployees = async () => {
    const res = await makeRequest(fetch(`${import.meta.env.VITE_BACKEND_URL}/employees`, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${store.token}`
        }
    }))

    if (res.status === 200) return { status: 200, data: res.data };

    return { status: res.status, errors: [] };
}

const createEmployee = async (user: Employee) => {
    const res = await makeRequest(fetch(`${import.meta.env.VITE_BACKEND_URL}/employees`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${store.token}`
        },
        body: JSON.stringify(user)
    }))

    if (res.status === 201)
        return { status: 200, message: `Employee ${user.username} created successfully` };

    if (res.status === 400)
        return { status: 400, errors: res?.errors }

    return { status: res.status, errors: [] };
}

const updateEmployee = async (employee: Employee) => {
    const res = await makeRequest(fetch(`${import.meta.env.VITE_BACKEND_URL}/employees`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${store.token}`
        },
        body: JSON.stringify(employee)
    }))

    if (res.status === 200)
        return { status: 200, message: `Employee ${employee.username} updated successfully` };

    if (res.status === 400)
        return { status: 400, errors: res?.errors }

    return { status: res.status, errors: [] };
}

const deleteEmployee = async (id: number) => {
    const res = await makeRequest(fetch(`${import.meta.env.VITE_BACKEND_URL}/employees/${id}`, {
        headers: {
            'Authorization': `Bearer ${store.token}`
        },
        method: "DELETE"
    }))

    if (res.status === 204) {
        return { status: 200, message: 'Employee deleted successfully' };
    }

    return { status: res.status, errors: [] };
}

export { getEmployees, updateEmployee, deleteEmployee, createEmployee, setAlert }