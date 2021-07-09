var trace1 = {
  x: [1, 2, 3, 4],
  y: [10, 15, 13, 17],
  name: 'This Week',
  type: 'scatter'
};

var trace2 = {
  x: [1, 2, 3, 4],
  y: [16, 5, 11, 9],
  name: 'Last Week',
  type: 'scatter'
};

var data = [trace1, trace2];

Plotly.newPlot('myDiv', data);
