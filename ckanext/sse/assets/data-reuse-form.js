/* Data Reuse Form Module
 * Handles dynamic form behavior for data reuse submission forms
 */
this.ckan.module('data-reuse-form', function ($) {
  return {
    /* options object can be extended using data-module-* attributes */
    options: {
      submissionTypeSelector: '#submission_type',
      showcasePermissionSelector: '#showcase_permission',
      usageExampleFieldSelector: '#usage_example_field',
      usageIdeaFieldSelector: '#usage_idea_field',
      showcaseOtherFieldSelector: '#showcase_other_field'
    },

    /* Initializes the module setting up elements and event listeners */
    initialize: function () {
      console.log('Data reuse form module initialized');
      
      // Cache DOM elements
      this.submissionTypeSelect = $(this.options.submissionTypeSelector);
      this.showcasePermissionSelect = $(this.options.showcasePermissionSelector);
      this.usageExampleField = $(this.options.usageExampleFieldSelector);
      this.usageIdeaField = $(this.options.usageIdeaFieldSelector);
      this.showcaseOtherField = $(this.options.showcaseOtherFieldSelector);
      this.form = this.el;

      // Set up event listeners
      this.submissionTypeSelect.on('change', $.proxy(this.toggleContentFields, this));
      this.showcasePermissionSelect.on('change', $.proxy(this.toggleShowcaseOther, this));
      
      // Enable Bootstrap 5 form validation
      this.form.on('submit', $.proxy(this.handleFormSubmit, this));

      // Initialize form state
      this.toggleContentFields();
      this.toggleShowcaseOther();
    },

    /* Toggles visibility of content fields based on submission type */
    toggleContentFields: function () {
      var submissionType = this.submissionTypeSelect.val();
      
      if (submissionType === 'Example') {
        this.showField(this.usageExampleField);
        this.hideField(this.usageIdeaField);
        // Make usage example required when visible
        this.usageExampleField.find('textarea').attr('required', 'required');
        this.usageIdeaField.find('textarea').removeAttr('required');
      } else if (submissionType === 'Idea') {
        this.hideField(this.usageExampleField);
        this.showField(this.usageIdeaField);
        // Make usage idea required when visible
        this.usageIdeaField.find('textarea').attr('required', 'required');
        this.usageExampleField.find('textarea').removeAttr('required');
      } else {
        // Show both fields if no specific type is selected, but neither required
        this.showField(this.usageExampleField);
        this.showField(this.usageIdeaField);
        this.usageExampleField.find('textarea').removeAttr('required');
        this.usageIdeaField.find('textarea').removeAttr('required');
      }
    },

    /* Toggles visibility of showcase other field based on showcase permission */
    toggleShowcaseOther: function () {
      var showcasePermission = this.showcasePermissionSelect.val();
      
      if (showcasePermission === 'Others') {
        this.showField(this.showcaseOtherField);
        // Make showcase other field required when visible
        this.showcaseOtherField.find('textarea').attr('required', 'required');
      } else {
        this.hideField(this.showcaseOtherField);
        this.showcaseOtherField.find('textarea').removeAttr('required');
      }
    },

    /* Smoothly shows a field */
    showField: function (field) {
      field.removeClass('hiding').show();
      // Trigger focus styling for required fields
      this.updateFieldStyling(field);
    },

    /* Smoothly hides a field */
    hideField: function (field) {
      field.addClass('hiding');
      var self = this;
      setTimeout(function() {
        field.hide().removeClass('hiding');
        self.updateFieldStyling(field);
      }, 300);
    },

    /* Update field styling based on required status */
    updateFieldStyling: function (field) {
      var input = field.find('input, textarea, select');
      var label = field.find('label');
      
      if (input.attr('required')) {
        label.addClass('control-required');
        input.addClass('required');
      } else {
        label.removeClass('control-required');
        input.removeClass('required');
      }
    },

    /* Handle form submission with Bootstrap 5 validation */
    handleFormSubmit: function (event) {
      var form = this.form[0];
      
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      
      form.classList.add('was-validated');
    },

    /* Called when the module is removed from the page */
    teardown: function () {
      // Clean up event listeners
      this.submissionTypeSelect.off('change', this.toggleContentFields);
      this.showcasePermissionSelect.off('change', this.toggleShowcaseOther);
    }
  };
});