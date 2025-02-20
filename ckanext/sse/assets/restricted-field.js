ckan.module("restricted-select", function ($, _) {
  "use strict";
  return {
    options: {
      debug: false,
    },

    initialize: function () {
      $(document).ready(function () {
        const restrictedVisibilityId = "#field-private-option-restricted";
        const restrictedOption = $(restrictedVisibilityId);
        const isRestrictedField = $("#field-is_restricted");
        let visibilitySelect = restrictedOption.parent();
        const isRestricted = isRestrictedField
          .find("option")
          .eq(1)
          .is(":selected");

        if (isRestricted) {
          const parentOfTheVisibilitySelect = visibilitySelect.parent();
          visibilitySelect.find("option").eq(1).removeAttr("selected");
          restrictedOption.attr("selected", "selected");
          const newOne = visibilitySelect.clone(true, true);
          visibilitySelect.detach();
          parentOfTheVisibilitySelect.append(newOne);
          visibilitySelect = newOne;
        }

        visibilitySelect.change((ev) => {
            const selectedOption = $(ev.target).find("option:selected");
            if (selectedOption.attr("id") === "field-private-option-restricted") {
              isRestrictedField.find("option").eq(1).attr("selected", "selected");
            } else {
              isRestrictedField.find("option").eq(2).attr("selected", "selected");
            }
          });
      });
    },
  };
});
