import { User } from "../pages/inc/Types";
import { setStore } from "../store";

const getUsers = async () => {
    const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/users`, {
        headers: {
            'Content-Type': 'application/json'
        }
    })

    if (res.status === 200) {
        let data = await res.json();

        return {status: 200, data: data.users};
    }

    return {status:res.status, errors: []};
}

const createUser = async (user: User) => {
    const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/users`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(user)
    })

    if (res.status === 200) {
        return {status: 200, message: `User ${user.username} created successfully`};
    }

    return {status:res.status, errors: []};
}

const updateUser = async (user: User) => {
    const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/users/${user.id}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(user)
    })

    if (res.status === 200) {
        return {status: 200, message: `User ${user.username} updated successfully`};
    }

    return {status:res.status, errors: []};
}

const deleteUser = async (id: number) => {
    const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/users/${id}`, {
        method: "DELETE"
    })

    if (res.status === 200) {
        let data = await res.json();
        setStore({message: data.message});

        return {status: 200, message: data.message};
    }

    return {status:res.status, errors: []};
}

export {getUsers, updateUser, deleteUser, createUser}