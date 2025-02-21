import React from 'react';
import PropTypes from 'prop-types';
import { X, CheckCircle, AlertTriangle, XCircle, Info } from 'lucide-react';

const variants = {
  success: {
    icon: CheckCircle,
    className: 'bg-green-50 text-green-800 border-green-200'
  },
  error: {
    icon: XCircle,
    className: 'bg-red-50 text-red-800 border-red-200'
  },
  warning: {
    icon: AlertTriangle,
    className: 'bg-yellow-50 text-yellow-800 border-yellow-200'
  },
  info: {
    icon: Info,
    className: 'bg-blue-50 text-blue-800 border-blue-200'
  }
};

const Toast = ({
  variant = 'info',
  title,
  message,
  onClose,
  duration = 5000
}) => {
  React.useEffect(() => {
    if (duration && onClose) {
      const timer = setTimeout(onClose, duration);
      return () => clearTimeout(timer);
    }
  }, [duration, onClose]);

  const Icon = variants[variant].icon;

  return (
    <div
      className={`
        rounded-lg border p-4 mb-4
        ${variants[variant].className}
      `}
    >
      <div className="flex items-start">
        <Icon className="h-5 w-5 mr-3" />
        <div className="flex-1">
          {title && (
            <h3 className="text-sm font-medium mb-1">{title}</h3>
          )}
          {message && (
            <p className="text-sm">{message}</p>
          )}
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="ml-3 inline-flex"
          >
            <X className="h-5 w-5" />
          </button>
        )}
      </div>
    </div>
  );
};

Toast.propTypes = {
  variant: PropTypes.oneOf(Object.keys(variants)),
  title: PropTypes.string,
  message: PropTypes.string,
  onClose: PropTypes.func,
  duration: PropTypes.number
};

export default Toast;
