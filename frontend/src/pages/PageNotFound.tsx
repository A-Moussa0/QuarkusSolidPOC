import { A } from '@solidjs/router';
import { Component } from 'solid-js';

const PageNotFound: Component = () => {
    return (
        <div class="d-flex align-items-center justify-content-center vh-100 text-light">
            <div class="text-center">
                <h1 class="display-1 fw-bold">404</h1>
                <p class="fs-3"> <span class="text-danger">Opps!</span> Page not found.</p>
                <p class="lead">
                    The page you’re looking for doesn’t exist.
                  </p>
                <A href="/" class="btn btn-primary">Go Home</A>
            </div>
        </div>
    )
}

export default PageNotFound;