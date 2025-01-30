import React from 'react';

const StatBox = ({ label, value, color }) => (
  <div className="text-center">
    <div className={`text-${color}-600 font-medium`}>{label}</div>
    <div className="text-2xl font-bold mt-1">{value}</div>
  </div>
);

const UserStats = ({ stats }) => {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-semibold mb-6">Users Statistics</h2>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatBox label="Active" value={stats.active} color="green" />
        <StatBox label="Expired" value={stats.expired} color="red" />
        <StatBox label="Expired in 24h" value={stats.expiredSoon} color="yellow" />
        <StatBox label="Deactive" value={stats.deactive} color="gray" />
        <StatBox label="Online" value={stats.online} color="blue" />
      </div>
    </div>
  );
};

export default UserStats;
