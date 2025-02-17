ckan.module("resource-geospatial", function($, _) {
    "use strict";
    return {
        options: {
            debug: false,
        },
        initialize: function() {
            const isGeospatialEl = $("#field-is_geospatial");
            const resourceTypeEl = $("#field-resource_type");
            resourceTypeEl.on("change", (e) => {
                const value = e.target.value;
                if (value != "regular") {
                    isGeospatialEl.val("False");
                    isGeospatialEl.attr("disabled", true);
                } else {
                    isGeospatialEl.attr("disabled", false);
                }
            });
        },
    };
});
