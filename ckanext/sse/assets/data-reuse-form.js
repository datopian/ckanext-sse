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
      this.showcasePermissionSelect = $(this.options.showcasePermissionSelector);
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


ckan.module('data-reuse-rejection-modal', function($) {
  return {
    options: {
      modalSelector: "#rejectModal",
      feedbackSelector: "#feedback",
      rejectUrl: null,
    },
    initialize: function() {
      // Create modal dynamically if it doesn't exist
      this.createModalIfNotExists();
      
      // Cache DOM elements
      this.modal = $(this.options.modalSelector);
      this.form = $(this.options.modalSelector + " form");
      this.feedback = $(this.options.feedbackSelector);
      
      // Get submission ID and reject URL from the button element
      this.submissionId = this.el.data("submission-id");
      this.rejectUrl = this.el.data("reject-url");
      
      // Set up click handler for this button
      this.el.on("click", $.proxy(this.handleButtonClick, this));
      
      // Set up event listeners for modal
      this.modal.on("show.bs.modal", $.proxy(this.handleModalShow, this));
      this.modal.on("hidden.bs.modal", $.proxy(this.handleModalHidden, this));
    },
    createModalIfNotExists: function() {
      var existingModal = document.getElementById('rejectModal');
      if (!existingModal) {
        var modalHtml = `
          <div class="modal fade" id="rejectModal" tabindex="-1" aria-labelledby="rejectModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="rejectModalLabel">Reject Submission</h5>
                  <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="rejectForm" method="post" action="/data_reuse/reject_data_reuse">
                  <div class="modal-body">
                    <div class="mb-3">
                      <label for="feedback" class="form-label">Feedback for the submitter</label>
                      <textarea class="form-control" id="feedback" name="feedback" rows="6" 
                                placeholder="Please provide constructive feedback explaining why this submission was rejected and what improvements could be made..."></textarea>
                      <div class="form-text">This feedback will be sent to the submitter via email.</div>
                    </div>
                    
                    <div class="alert alert-warning">
                      <i class="fa fa-exclamation-triangle"></i>
                      <strong>Warning:</strong> This action cannot be undone. The submission will be marked as rejected and the submitter will be notified.
                    </div>
                  </div>
                  <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-warning">
                      <i class="fa fa-times"></i> Reject Submission
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        `;
        $('body').append(modalHtml);
      }
    },
    handleButtonClick: function(event) {
      event.preventDefault();
      
      // Update form action with reject URL
      if (this.form.length && this.rejectUrl) {
        this.form.attr("action", this.rejectUrl);
      }
      
      // Clear previous feedback
      if (this.feedback.length) {
        this.feedback.val("");
      }
      
      // Show modal
      this.modal.modal("show");
    },
    handleModalShow: function(event) {
      // Modal is shown, form action already updated in handleButtonClick
    },
    handleModalHidden: function(event) {
      // Clear feedback when modal is hidden
      if (this.feedback.length) {
        this.feedback.val("");
      }
    }
  };
});