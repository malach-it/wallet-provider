function sortTable(order) {
    var table, rows, switching, i, x, y, shouldSwitch;
    table = document.getElementById("tableDashboard");
    switching = true;

    while (switching) {
        switching = false;
        rows = table.rows;

        for (i = 1; i < (rows.length - 1); i++) {
            shouldSwitch = false;

            x = rows[i].getElementsByTagName("TD")[0].textContent.toLowerCase();
            y = rows[i + 1].getElementsByTagName("TD")[0].textContent.toLowerCase();

            if ((order === 'asc' && x > y) || (order === 'desc' && x < y)) {
                shouldSwitch = true;
                break;
            }
        }

        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
        sortTable('asc');
    });
}
