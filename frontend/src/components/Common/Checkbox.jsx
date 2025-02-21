import React from 'react';
import PropTypes from 'prop-types';

const Checkbox = ({
  label,
  checked,
  onChange,
  disabled = false,
  error,
  className = '',
  labelClassName = ''
}) => {
  return (
    <div className={`flex items-start ${className}`}>
      <div className="flex items-center h-5">
        <input
          type="checkbox"
          checked={checked}
          onChange={onChange}
          disabled={disabled}
          className={`
            h-4 w-4 rounded border-gray-300 text-blue-600
            focus:ring-blue-500 disabled:opacity-50
            ${error ? 'border-red-500' : ''}
          `}
        />
      </div>
      {label && (
        <div className="ml-3 text-sm">
          <label
            className={`
              text-gray-700 
              ${disabled ? 'opacity-50' : ''}
              ${error ? 'text-red-500' : ''}
              ${labelClassName}
            `}
          >
            {label}
          </label>
          {error && (
            <p className="mt-1 text-sm text-red-500">{error}</p>
          )}
        </div>
      )}
    </div>
  );
};

Checkbox.propTypes = {
  label: PropTypes.node,
  checked: PropTypes.bool.isRequired,
  onChange: PropTypes.func.isRequired,
  disabled: PropTypes.bool,
  error: PropTypes.string,
  className: PropTypes.string,
  labelClassName: PropTypes.string
};

export default Checkbox;
