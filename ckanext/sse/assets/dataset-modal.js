ckan.module("dataset-review-modal", function($, _) {
    "use strict";
    return {
        options: {
            debug: false,
        },

        initialize: function() {
            const openModalButtonEl = $(this.el);
            const openModalButtonName = $(this.el).attr("name") || "Unnamed Button";
            const openModalButtonValue = $(this.el).attr("value") || "No Value";

            const modalEl = $(`
                <div style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); z-index: 1000;">
                    <div class="modal-container" style="background: white; max-width: 500px; margin: 20% auto; padding: 20px; width: 100%; border-radius: 8px; position: relative; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <div style="display: flex;">
                            <h2>Confirm Your Changes</h2>
                        </div>
                        <div style="display: flex; align-items: center;">
                            <p style="text-align: left;">
                                Please review the information you’ve provided. By proceeding, you
                                confirm that the data is accurate and complete to the best of your
                                knowledge.
                            </p>
                        </div>
                        <div style="display: flex; justify-content: flex-end; gap: 0.5rem">
                            <button id="modal-close-btn" class="btn btn-danger" type="button">
                                Cancel
                            </button>
                            <button
                                id="modal-confirm-btn"
                                class="btn btn-success"
                                type="submit"
                                name="${openModalButtonName}"
                                value="${openModalButtonValue}"
                            >
                                Confirm
                            </button>
                        </div>
                    </div>
                </div>`);

            modalEl.insertAfter(openModalButtonEl);

            this._openModal = () => {
                modalEl.css("display", "block");
            };

            this._closeModal = () => {
                modalEl.css("display", "none");
            };

            const modalCloseBtnEl = modalEl.find("#modal-close-btn");
            modalCloseBtnEl.on("click", this._closeModal);
            openModalButtonEl.on("click", this._openModal);

            $(modalEl).on("click", (e) => {
                if (!$(e.target).closest(".modal-container").length) {
                    this._closeModal();
                }
            });
        },
    };
});
