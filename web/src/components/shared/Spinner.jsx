import React from 'react';
import './Spinner.css';

/**
 * Spinner - A loading indicator
 * @param {'sm' | 'md' | 'lg'} props.size - Spinner size
 * @param {string} props.className - Additional class names
 */
const Spinner = ({ size = 'md', className = '' }) => {
  return (
    <div className={`spinner spinner--${size} ${className}`}>
      <div className="spinner-ring"></div>
    </div>
  );
};

export default Spinner;
