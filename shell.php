<?php
/**
 * 高级flag搜索器
 */

class AdvancedFlagHunter {
    private $results = [];
    private $options = [
        'max_depth' => 10,
        'max_file_size' => 5242880, // 5MB
        'extensions' => ['txt', 'php', 'html', 'js', 'json', 'xml', 'md'],
        'skip_dirs' => ['.git', 'node_modules', 'vendor', '__pycache__'],
    ];
    
    public function __construct($options = []) {
        $this->options = array_merge($this->options, $options);
    }
    
    public function hunt($dir = '.') {
        $this->walk($dir, 0);
        return $this->results;
    }
    
    private function walk($dir, $depth) {
        if ($depth > $this->options['max_depth']) {
            return;
        }
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            
            foreach ($iterator as $file) {
                $path = $file->getPathname();
                
                // 跳过指定目录
                foreach ($this->options['skip_dirs'] as $skipDir) {
                    if (strpos($path, DIRECTORY_SEPARATOR . $skipDir) !== false) {
                        continue 2;
                    }
                }
                
                // 检查文件扩展名
                if ($file->isFile()) {
                    $ext = $file->getExtension();
                    if (!empty($this->options['extensions']) && 
                        !in_array(strtolower($ext), $this->options['extensions'])) {
                        continue;
                    }
                    
                    $this->checkFile($file);
                }
                
                // 检查目录名
                if ($file->isDir()) {
                    $this->checkDir($file);
                }
            }
        } catch (Exception $e) {
            error_log("搜索错误: " . $e->getMessage());
        }
    }
    
    private function checkFile($file) {
        $path = $file->getPathname();
        $size = $file->getSize();
        
        if ($size > $this->options['max_file_size']) {
            return;
        }
        
        // 检查文件名
        $this->checkFileName($file->getFilename(), $path);
        
        // 检查文件内容
        if (is_readable($path)) {
            $content = @file_get_contents($path);
            if ($content !== false) {
                $this->checkContent($content, $path);
            }
        }
    }
    
    private function checkFileName($filename, $path) {
        $patterns = [
            '/flag/i',
            '/ctf/i',
            '/secret/i',
            '/password/i',
            '/key/i',
            '/token/i',
            '/\.env$/',
            '/config$/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $filename)) {
                $this->addResult('可疑文件名', $path, $filename);
            }
        }
    }
    
    private function checkContent($content, $path) {
        // 常见flag格式
        $patterns = [
            '/flag{[^}]+}/i',
            '/ctf{[^}]+}/i',
            '/[a-f0-9]{32}/i',  // MD5
            '/[a-f0-9]{40}/i',  // SHA1
            '/[a-f0-9]{64}/i',  // SHA256
            '/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/i', // UUID
        ];
        
        // 关键词
        $keywords = [
            'flag',
            'ctf',
            'secret',
            'password',
            'key',
            'token',
            'admin',
            'root',
            'credentials',
        ];
        
        // 检查模式
        foreach ($patterns as $pattern) {
            if (preg_match_all($pattern, $content, $matches)) {
                foreach ($matches[0] as $match) {
                    $this->addResult('模式匹配', $path, $match);
                }
            }
        }
        
        // 检查关键词
        foreach ($keywords as $keyword) {
            $lines = explode("\n", $content);
            foreach ($lines as $lineNum => $line) {
                if (stripos($line, $keyword) !== false) {
                    $line = trim($line);
                    if (strlen($line) > 100) {
                        $line = substr($line, 0, 100) . '...';
                    }
                    $this->addResult(
                        "关键词: $keyword", 
                        $path, 
                        "行 " . ($lineNum + 1) . ": " . $line
                    );
                }
            }
        }
    }
    
    private function checkDir($dir) {
        $dirname = basename($dir->getPathname());
        if (preg_match('/(flag|ctf|secret|backup)/i', $dirname)) {
            $this->addResult('可疑目录名', $dir->getPathname(), '');
        }
    }
    
    private function addResult($type, $path, $content) {
        $this->results[] = [
            'type' => $type,
            'path' => $path,
            'content' => $content,
            'time' => date('H:i:s'),
        ];
    }
    
    public function getReport() {
        $report = "高级Flag搜索报告\n";
        $report .= "生成时间: " . date('Y-m-d H:i:s') . "\n";
        $report .= "搜索深度: " . $this->options['max_depth'] . "\n";
        $report .= "最大文件: " . ($this->options['max_file_size'] / 1024 / 1024) . "MB\n";
        $report .= "=" . str_repeat("=", 60) . "\n\n";
        
        $groups = [];
        foreach ($this->results as $result) {
            $groups[$result['type']][] = $result;
        }
        
        foreach ($groups as $type => $items) {
            $report .= "[$type] 找到 " . count($items) . " 个结果:\n";
            foreach ($items as $item) {
                $report .= "  • 文件: " . $item['path'] . "\n";
                if (!empty($item['content'])) {
                    $report .= "    内容: " . $item['content'] . "\n";
                }
                $report .= "    时间: " . $item['time'] . "\n";
            }
            $report .= "\n";
        }
        
        $report .= "总计找到: " . count($this->results) . " 个可疑项目\n";
        return $report;
    }
}

// HTML头部
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>高级Flag搜索器</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 0.95em;
            opacity: 0.9;
        }
        
        .content {
            padding: 30px;
        }
        
        .button-group {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
        }
        
        button {
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        button:active {
            transform: translateY(0);
        }
        
        .results {
            display: none;
        }
        
        .results.show {
            display: block;
        }
        
        .result-group {
            margin-bottom: 25px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }
        
        .result-group h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        
        .result-item {
            background: #f8f9fa;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            border-left: 3px solid #764ba2;
        }
        
        .result-item .label {
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        
        .result-item .content {
            background: white;
            padding: 10px;
            border-radius: 3px;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            color: #d9534f;
            font-weight: bold;
        }
        
        .result-item .path {
            color: #666;
            font-size: 0.9em;
            margin-top: 8px;
            word-break: break-all;
        }
        
        .result-item .time {
            color: #999;
            font-size: 0.85em;
            margin-top: 5px;
        }
        
        .no-results {
            text-align: center;
            padding: 40px;
            color: #999;
            font-size: 1.1em;
        }
        
        .summary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .summary .count {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #667eea;
            display: none;
        }
        
        .loading.show {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 高级Flag搜索器</h1>
            <p>在当前目录及子目录中搜索可能的flag和敏感信息</p>
        </div>
        
        <div class="content">
            <div class="button-group">
                <button onclick="startSearch()">开始搜索</button>
                <button onclick="clearResults()">清除结果</button>
            </div>
            
            <div class="loading" id="loading">
                <p>正在搜索中，请稍候...</p>
            </div>
            
            <div class="results" id="results"></div>
        </div>
    </div>
    
    <script>
        function startSearch() {
            document.getElementById('loading').classList.add('show');
            document.getElementById('results').classList.remove('show');
            
            fetch('<?php echo $_SERVER['PHP_SELF']; ?>', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=search'
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('loading').classList.remove('show');
                displayResults(data);
            })
            .catch(error => {
                document.getElementById('loading').classList.remove('show');
                alert('搜索出错: ' + error);
            });
        }
        
        function displayResults(data) {
            const resultsDiv = document.getElementById('results');
            
            if (data.results.length === 0) {
                resultsDiv.innerHTML = '<div class="no-results">✗ 未找到任何可疑flag或敏感信息</div>';
            } else {
                let html = '<div class="summary"><div>搜索完成！找到</div><div class="count">' + data.results.length + '</div><div>个可疑项目</div></div>';
                
                const groups = {};
                data.results.forEach(result => {
                    if (!groups[result.type]) {
                        groups[result.type] = [];
                    }
                    groups[result.type].push(result);
                });
                
                Object.keys(groups).forEach(type => {
                    html += '<div class="result-group">';
                    html += '<h3>' + type + ' - 找到 ' + groups[type].length + ' 个结果</h3>';
                    
                    groups[type].forEach(item => {
                        html += '<div class="result-item">';
                        html += '<div class="label">文件路径：</div>';
                        html += '<div class="path">' + escapeHtml(item.path) + '</div>';
                        
                        if (item.content) {
                            html += '<div class="label" style="margin-top: 10px;">内容/信息：</div>';
                            html += '<div class="content">' + escapeHtml(item.content) + '</div>';
                        }
                        
                        html += '<div class="time">检测时间：' + item.time + '</div>';
                        html += '</div>';
                    });
                    
                    html += '</div>';
                });
                
                resultsDiv.innerHTML = html;
            }
            
            resultsDiv.classList.add('show');
        }
        
        function clearResults() {
            document.getElementById('results').classList.remove('show');
            document.getElementById('results').innerHTML = '';
        }
        
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, m => map[m]);
        }
    </script>
</body>
</html>

<?php
// 处理AJAX请求
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'search') {
    $hunter = new AdvancedFlagHunter([
        'max_depth' => 5,
        'max_file_size' => 2 * 1024 * 1024, // 2MB
        'extensions' => ['txt', 'php', 'html', 'js', 'json', 'md', 'yml', 'yaml', 'ini'],
    ]);
    
    $results = $hunter->hunt('.');
    
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['results' => $results]);
    exit;
}
?>
