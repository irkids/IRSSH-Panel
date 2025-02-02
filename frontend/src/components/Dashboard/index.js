import React, { useState, useEffect } from 'react';
import axios from '../../config/axios';
import ResourceStats from './ResourceStats';
import BandwidthStats from './BandwidthStats';
import ProtocolStats from './ProtocolStats';
import UserStats from './UserStats';
import MainLayout from '../../layouts/MainLayout';

const Dashboard = () => {
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [data, setData] = useState({
        resources: { cpu: 0, ram: 0, disk: 0 },
        bandwidth: {
            monthly: [],
            daily: []
        },
        protocols: [],
        users: {
            active: 0,
            expired: 0,
            expiredSoon: 0,
            deactive: 0,
            online: 0
        }
    });

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get('/api/monitoring/system');
                setData(response.data);
                setError(null);
            } catch (err) {
                console.error('Error fetching dashboard data:', err);
                setError('Failed to load dashboard data');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <MainLayout>
                <div className="flex justify-center items-center h-full">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900"></div>
                </div>
            </MainLayout>
        );
    }

    if (error) {
        return (
            <MainLayout>
                <div className="flex justify-center items-center h-full">
                    <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                        {error}
                    </div>
                </div>
            </MainLayout>
        );
    }

    return (
        <MainLayout>
            <div className="p-6 space-y-6">
                <ResourceStats
                    cpuUsage={data.resources.cpu}
                    ramUsage={data.resources.ram}
                    diskUsage={data.resources.disk}
                />
                <BandwidthStats
                    monthlyData={data.bandwidth.monthly}
                    dailyData={data.bandwidth.daily}
                />
                <ProtocolStats protocols={data.protocols} />
                <UserStats stats={data.users} />
            </div>
        </MainLayout>
    );
};

export default Dashboard;
