import { Component, lazy } from 'solid-js';
import { Routes, Route } from "@solidjs/router"
import { logout } from '../utils/Auth';
const Employees = lazy(() => import("../pages/Employees"));
const Home = lazy(() => import("../pages/Home"));
const Authenticate = lazy(() => import("../pages/Authenticate"));
// const Signup = lazy(() => import("../pages/Signup"));
const PageNotFound = lazy(() => import("../pages/PageNotFound"));

const index: Component = () => {
    return (
        <Routes>
            <Route path="/" component={Home} />
            {/* <Route path="/login" component={Login} /> */}
            {/* <Route path="/signup" component={Signup} /> */}
            <Route path="/authenticate" component={Authenticate} />
            <Route path="/employees" component={Employees} />
            <Route path="/logout" element={<>{logout}</>} />
            <Route path="*" component={PageNotFound} />
        </Routes>
    )
}

export default index;