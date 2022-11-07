import { Component, lazy } from 'solid-js';
import { Routes, Route } from "@solidjs/router"
import { logout } from '../components/Auth';
const Users = lazy(() => import("../pages/Users"));
const Home = lazy(() => import("../pages/Home"));
const Login = lazy(() => import("../pages/Login"));
const Signup = lazy(() => import("../pages/Signup"));
const PageNotFound = lazy(() => import("../pages/PageNotFound"));

const index: Component = () => {
    return (
        <Routes>
            <Route path="/" component={Home} />
            <Route path="/login" component={Login} />
            <Route path="/signup" component={Signup} />
            <Route path="/users" component={Users} />
            <Route path="/logout" element={<>{logout}</>} />
            <Route path="*" component={PageNotFound} />
        </Routes>
    )
}

export default index;