import React, { useState } from 'react';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const [usernameExists, setUsernameExists] = useState(null);

  const handleCheckUsername = async (value) => {
    setUsername(value);
    if (value.trim() !== ''){
    try {

      const response = await fetch(`/check-username/${value}`);
      const data = await response.json();
      
      setUsernameExists(data.exists);
    
    } catch (error) {
      console.error('Error:', error);
    }}
  };

  const fetchProtectedRoute = async () => {
    try {
      const response = await fetch('/protected-route', {
        method: 'GET',
        credentials: 'include',
      });
  
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
  
      const data = await response.text();
      alert(data);
    } catch (error) {
      console.error('There was a problem with the fetch operation:', error);
    }
  };
  
  const fetchLogout = async () => {
    try {
      const response = await fetch('/logout', {
        method: 'GET',
        credentials: 'include',
      });
  
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
  
      const data = await response.text();
      alert(data);
    } catch (error) {
      console.error('There was a problem with the fetch operation:', error);
    }
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ uname: username, pw: password }),
      });

      const data = await response.text();
      alert(data);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  return (
    <div className="login-form">
            {usernameExists !== null && (
        <p>{usernameExists ? '✔️' : '❌'}</p>
      )}
      <form>
        <label>    
          <input type="text" value={username} onInput={(e) => { handleCheckUsername(e.target.value); }} />
        </label>
        <br />
        <label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <br />      
      </form>
      <button onClick={handleSubmit}>Login</button>
      <button onClick={fetchProtectedRoute}>Fetch</button>
      <button onClick={fetchLogout}>Logout</button>
    </div>
  );
}

export default App;

