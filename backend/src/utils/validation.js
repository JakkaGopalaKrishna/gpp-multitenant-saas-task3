const validateInput = (obj, rules) => {
  const errors = {};

  for (const [field, rule] of Object.entries(rules)) {
    const value = obj[field];

    if (rule.required && (!value || value.toString().trim() === '')) {
      errors[field] = `${field} is required`;
      continue;
    }

    if (value && rule.type === 'email') {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(value)) {
        errors[field] = `${field} must be a valid email`;
      }
    }

    if (value && rule.minLength && value.toString().length < rule.minLength) {
      errors[field] = `${field} must be at least ${rule.minLength} characters`;
    }

    if (value && rule.enum && !rule.enum.includes(value)) {
      errors[field] = `${field} must be one of: ${rule.enum.join(', ')}`;
    }

    if (value && rule.pattern && !rule.pattern.test(value)) {
      errors[field] = `${field} format is invalid`;
    }
  }

  return errors;
};

module.exports = { validateInput };
