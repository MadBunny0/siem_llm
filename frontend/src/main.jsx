// Точка входа фронтенда: глобальные стили и корневой компонент авторизации.
import { createRoot } from 'react-dom/client';
import './styles.css';
import AuthGate from './components/AuthGate.jsx';

createRoot(document.getElementById('root')).render(<AuthGate />);
