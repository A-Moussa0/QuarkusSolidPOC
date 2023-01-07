import { Component, onMount, onCleanup } from 'solid-js';
import Router from './router';
import Header from './pages/inc/Header';
import Alert from './pages/inc/Alert';
import { refreshAccessToken } from './utils/LoginAction';

const App: Component = () => {
  let refreshAccessTokenInterval: number
  onMount( () => {
    refreshAccessTokenInterval = setInterval(() => refreshAccessToken(), 1000 * 60 * 4) // 4 mins
  })
  onCleanup( () => {
    clearInterval(refreshAccessTokenInterval)
  })

  return (
    <div class='bg-dark vh-100'>
      <Header />
      <div style="margin-top: 59px">
        <Alert />
        <Router />
      </div>
    </div >
  );
};

export default App;
