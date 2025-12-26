import React from 'react';
import './Card.css';

const Card = ({ title, value, subtext, icon: Icon, trend }) => {
    return (
        <div className="stat-card glass-panel">
            <div className="card-header">
                <span className="card-title">{title}</span>
                {Icon && <Icon size={20} className="card-icon" />}
            </div>
            <div className="card-content">
                <div className="card-value">{value}</div>
                {subtext && <div className="card-subtext">{subtext}</div>}
            </div>
            {trend && (
                <div className={`card-trend ${trend > 0 ? 'up' : 'down'}`}>
                    {trend > 0 ? '+' : ''}{trend}%
                </div>
            )}
        </div>
    );
};

export default Card;
