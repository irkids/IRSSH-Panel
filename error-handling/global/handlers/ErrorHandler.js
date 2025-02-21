class ErrorHandler {
  constructor() {
    this.errorTypes = {
      ValidationError: {
        statusCode: 400,
        message: 'Invalid input data'
      },
      AuthenticationError: {
        statusCode: 401,
        message: 'Authentication failed'
      },
      AuthorizationError: {
        statusCode: 403,
        message: 'Insufficient permissions'
      },
      NotFoundError: {
        statusCode: 404,
        message: 'Resource not found'
      },
      ConflictError: {
        statusCode: 409,
        message: 'Resource conflict'
      },
      RateLimitError: {
        statusCode: 429,
        message: 'Too many requests'
      }
    };
  }

  handle(error, req, res, next) {
    const errorType = this.errorTypes[error.name] || {
      statusCode: 500,
      message: 'Internal server error'
    };

    const response = {
      status: 'error',
      message: error.message || errorType.message,
      code: error.code,
      ...(process.env.NODE_ENV === 'development' && {
        stack: error.stack
      })
    };

    res.status(errorType.statusCode).json(response);
  }

  createError(name, message, code = null) {
    const error = new Error(message);
    error.name = name;
    error.code = code;
    return error;
  }
}

module.exports = new ErrorHandler();
