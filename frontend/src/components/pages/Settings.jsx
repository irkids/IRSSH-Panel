import React, { useState } from 'react';
import { Save, RefreshCw } from 'lucide-react';
import Button from '../components/common/Button';
import Input from '../components/common/Input';
import Alert from '../components/common/Alert';
import { useApi } from '../services/api';

const Settings = () => {
  const [settings, setSettings] = useState({
    appName: 'IRSSH Panel',
    maxConnections: 1000,
    sessionTimeout: 3600,
    emailNotifications: true,
    loggingLevel: 'info',
    backupEnabled: true,
    backupInterval: 24,
    monitoringEnabled: true
  });
  
  const [loading, setLoading]
