import { Component } from 'solid-js';
import Router from './router';
import Header from './pages/inc/Header';
import Alert from './pages/inc/Alert';


const App: Component = () => {
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
