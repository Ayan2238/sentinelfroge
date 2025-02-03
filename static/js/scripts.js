document.addEventListener("DOMContentLoaded", () => {
    // Fetch report data
    fetch("/api/report-data")
        .then(response => response.json())
        .then(data => {
            // Update vulnerability chart
            updateChart(data.vulnerabilities);

            // Render attack paths
            renderAttackPaths(data.attack_paths);

            // Display data leaks
            renderDataLeaks(data.data_leaks);

            // Show AI recommendations
            renderRecommendations(data.recommendations);
        });

    function updateChart(vulns) {
        const ctx = document.getElementById('vulnChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['XSS', 'SQLi', 'CSRF', 'JWT Issues'],
                datasets: [{
                    label: 'Vulnerability Count',
                    data: vulns,
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.5)',
                        'rgba(54, 162, 235, 0.5)',
                        'rgba(255, 206, 86, 0.5)',
                        'rgba(75, 192, 192, 0.5)'
                    ]
                }]
            }
        });
    }

    function renderAttackPaths(paths) {
        const svg = d3.select("#attackGraph").append("g");
        svg.selectAll("path")
            .data(paths)
            .enter()
            .append("path")
            .attr("d", d3.linkHorizontal())
            .attr("class", "attack-path");
    }

    function renderDataLeaks(leaks) {
        const leaksList = document.getElementById('dataLeaks');
        leaks.forEach(leak => {
            const li = document.createElement('li');
            li.className = 'list-group-item';
            li.textContent = leak;
            leaksList.appendChild(li);
        });
    }

    function renderRecommendations(recommendations) {
        const aiSection = document.getElementById('aiRecommendations');
        recommendations.forEach(rec => {
            const div = document.createElement('div');
            div.className = 'ai-recommendation';
            div.innerHTML = `
                <h4>${rec.title}</h4>
                <p>${rec.content}</p>
            `;
            aiSection.appendChild(div);
        });
    }
});
