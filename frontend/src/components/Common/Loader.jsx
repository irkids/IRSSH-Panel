import React from 'react';
import PropTypes from 'prop-types';

const sizes = {
  sm: 'h-4 w-4',
  md: 'h-8 w-8',
  lg: 'h-12 w-12',
  xl: 'h-16 w-16'
};

const variants = {
  primary: 'border-blue-600',
  secondary: 'border-gray-600',
  white: 'border-white'
};

const Loader = ({
  size = 'md',
  variant = 'primary',
  className = '',
  fullScreen = false
}) => {
  const loader = (
    <div
      className={`
        animate-spin rounded-full
        border-2 border-t-transparent
        ${sizes[size]}
        ${variants[variant]}
        ${className}
      `}
    />
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-white bg-opacity-75 z-50">
        {loader}
      </div>
    );
  }

  return loader;
};

Loader.propTypes = {
  size: PropTypes.oneOf(Object.keys(sizes)),
  variant: PropTypes.oneOf(Object.keys(variants)),
  className: PropTypes.string,
  fullScreen: PropTypes.bool
};

export default Loader;
