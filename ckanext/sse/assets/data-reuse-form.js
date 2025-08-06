/* Data Reuse Form Module
 * Handles dynamic form behavior for data reuse submission forms
 */
this.ckan.module("data-reuse-form", function ($) {
  return {
    /* options object can be extended using data-module-* attributes */
    options: {
      showcasePermissionSelector: "#showcase_permission",
      showcaseOtherFieldSelector: "#showcase_other_field",
    },

    /* Initializes the module setting up elements and event listeners */
    initialize: function () {
      console.log("Data reuse form module initialized");

      // Cache DOM elements
      this.submissionTypeSelect = $(this.options.submissionTypeSelector);
      this.showcasePermissionSelect = $(this.options.showcasePermissionSelector);
      this.usageExampleField = $(this.options.usageExampleFieldSelector);
      this.usageIdeaField = $(this.options.usageIdeaFieldSelector);
      this.showcaseOtherField = $(this.options.showcaseOtherFieldSelector);
      this.form = this.el;

      this.showcasePermissionSelect.on(
        "change",
        $.proxy(this.toggleShowcaseOther, this)
      );

      // Enable Bootstrap 5 form validation
      this.form.on("submit", $.proxy(this.handleFormSubmit, this));

      // Initialize form state
      this.toggleShowcaseOther();
    },

    /* Toggles visibility of showcase other field based on showcase permission */
    toggleShowcaseOther: function () {
      var showcasePermission = this.showcasePermissionSelect.val();

      if (showcasePermission === "Others") {
        this.showField(this.showcaseOtherField);
        // Make showcase other field required when visible
        this.showcaseOtherField.find("textarea").attr("required", "required");
      } else {
        this.hideField(this.showcaseOtherField);
        this.showcaseOtherField.find("textarea").removeAttr("required");
      }
    },

    /* Smoothly shows a field */
    showField: function (field) {
      field.removeClass("hiding").show();
      // Trigger focus styling for required fields
      this.updateFieldStyling(field);
    },

    /* Smoothly hides a field */
    hideField: function (field) {
      field.addClass("hiding");
      var self = this;
      setTimeout(function () {
        field.hide().removeClass("hiding");
        self.updateFieldStyling(field);
      }, 300);
    },

    /* Update field styling based on required status */
    updateFieldStyling: function (field) {
      var input = field.find("input, textarea, select");
      var label = field.find("label");

      if (input.attr("required")) {
        label.addClass("control-required");
        input.addClass("required");
      } else {
        label.removeClass("control-required");
        input.removeClass("required");
      }
    },

    /* Handle form submission with Bootstrap 5 validation */
    handleFormSubmit: function (event) {
      var form = this.form[0];

      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }

      form.classList.add("was-validated");
    },

    /* Called when the module is removed from the page */
    teardown: function () {
      if (
        this.showcasePermissionSelect &&
        this.showcasePermissionSelect.length
      ) {
        this.showcasePermissionSelect.off("change", this.toggleShowcaseOther);
      }
      if (this.form && this.form.length) {
        this.form.off("submit", this.handleFormSubmit);
      }
    },
  };
});
