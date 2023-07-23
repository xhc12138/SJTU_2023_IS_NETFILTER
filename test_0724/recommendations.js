// 获取URL参数，解析出推荐歌曲数据
function getRecommendedSongs() {
    const urlParams = new URLSearchParams(window.location.search);
    const recommendedSongsParam = urlParams.get('recommendedSongs');
    return JSON.parse(decodeURIComponent(recommendedSongsParam));
  }
  
// 创建表格
function createTable() {
    const table = document.createElement('table');
    const tableHeader = document.createElement('tr');
  
    const header1 = document.createElement('th');
    header1.textContent = '歌曲名称';
    tableHeader.appendChild(header1);
  
    const header2 = document.createElement('th');
    header2.textContent = '艺术家';
    tableHeader.appendChild(header2);
  
    const header3 = document.createElement('th'); // 新的表头列
    header3.textContent = '推荐次数';
    tableHeader.appendChild(header3);
  
    const header4 = document.createElement('th'); // 新的表头列
    header4.textContent = 'URL链接';
    tableHeader.appendChild(header4);
  
    table.appendChild(tableHeader);
    return table;
  }
  
  

// 在表格中添加行
function addTableRow(table, songName, artists, count, url) {
    const row = document.createElement('tr');
  
    const cell1 = document.createElement('td');
    cell1.textContent = songName;
    row.appendChild(cell1);
  
    const cell2 = document.createElement('td');
    cell2.textContent = artists.join(', ');
    row.appendChild(cell2);
  
    const cell3 = document.createElement('td');
    cell3.textContent = count;
    row.appendChild(cell3);
  
    const cell4 = document.createElement('td'); // 新的单元格
    if (url) {
      const link = document.createElement('a');
      link.href = url;
      link.textContent = 'Listen'; // You can customize the link text here
      link.target = '_blank'; // Open the link in a new tab
      cell4.appendChild(link);
    }
    row.appendChild(cell4);
  
    table.appendChild(row);
  }
  
// 获取访问令牌
async function getAccessToken() {
    const clientId = 'caeb3171fa9d48af9afdad43120efb40';
    const clientSecret = 'cf67f8e118e84669a428681b003e6a0c';
  
    const response = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret)
      },
      body: 'grant_type=client_credentials'
    });
  
    const data = await response.json();
    return data.access_token;
  }


// 获取歌曲URL链接
async function getSongUrl(songName) {
    const accessToken = await getAccessToken();
    const searchEndpoint = `https://api.spotify.com/v1/search?q=${encodeURIComponent(songName)}&type=track&limit=1`;
  
    try {
      const response = await axios.get(searchEndpoint, {
        headers: {
          'Authorization': 'Bearer ' + accessToken
        }
      });
  
      const track = response.data.tracks.items[0];
      if (track) {
        return track.external_urls.spotify;
      } else {
        return null;
      }
    } catch (error) {
      console.error('Error searching for the song:', error);
      return null;
    }
  }
  


  // 显示总推荐次数最多的10首歌曲
async function displayTopRecommendedSongs() {
    const recommendedSongs = getRecommendedSongs();
  
    // 对推荐歌曲按推荐次数进行降序排序
    const sortedSongs = recommendedSongs.sort((a, b) => b.count - a.count);
  
    // 选择推荐次数最多的前10首歌曲
    const top10RecommendedSongs = sortedSongs.slice(0, 10);
  
    // Display the top 10 most recommended songs in a table
    const table = createTable();
    for (const song of top10RecommendedSongs) {
      const songName = song.songName;
      const artists = song.artists;
      const count = song.count;
  
      // Fetch the URL link for the song
      const url = await getSongUrl(songName); // Wrap in an async function
  
      // Add a new row to the table with the song information and URL link
      addTableRow(table, songName, artists, count, url);
    }
  
    // Append the table to the result-container in the HTML
    const resultContainer = document.getElementById('result-container');
    resultContainer.appendChild(table);
  }
  
  
  // Call the displayTopRecommendedSongs function when the page loads
  window.addEventListener('load', () => {
    displayTopRecommendedSongs();
  });
  