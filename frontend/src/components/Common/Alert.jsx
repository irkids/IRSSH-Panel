import React from 'react';
import PropTypes from 'prop-types';
import { AlertTriangle, CheckCircle, Info, XCircle } from 'lucide-react';

const variants = {
  success: {
    bg: 'bg-green-50',
    border: 'border-green-400',
    text: 'text-green-700',
    icon: CheckCircle
  },
  error: {
    bg: 'bg-red-50',
    border: 'border-red-400',
    text: 'text-red-700',
    icon: XCircle
  },
  warning: {
    bg: 'bg-yellow-50',
    border: 'border-yellow-400',
    text: 'text-yellow-700',
    icon: AlertTriangle
  },
  info: {
    bg: 'bg-blue-50',
    border: 'border-blue-400',
    text: 'text-blue-700',
    icon: Info
  }
};

const Alert = ({
  variant = 'info',
  title,
  message,
  onClose,
  className = ''
}) => {
  const style = variants[variant];
  
  return (
    <div className={`
      p-4 rounded-md border
      ${style.bg}
      ${style.border}
      ${className}
    `}>
      <div className="flex">
        <div className="flex-shrink-0">
          <style.icon className={`h-5 w-5 ${style.text}`} />
        </div>
        <div className="ml-3">
          {title && (
            <h3 className={`text-sm font-medium ${style.text}`}>
              {title}
            </h3>
          )}
          {message && (
            <div className={`mt-2 text-sm ${style.text}`}>
              {message}
            </div>
          )}
        </div>
        {onClose && (
          <div className="ml-auto pl-3">
            <button
              className={`inline-flex rounded-md p-1.5 ${style.text} hover:${style.bg} focus:outline-none`}
              onClick={onClose}
            >
              <XCircle className="h-5 w-5" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

Alert.propTypes = {
  variant: PropTypes.oneOf(Object.keys(variants)),
  title: PropTypes.string,
  message: PropTypes.string,
  onClose: PropTypes.func,
  className: PropTypes.string
};

export default Alert;
