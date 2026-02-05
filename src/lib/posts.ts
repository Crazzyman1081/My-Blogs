import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { remark } from 'remark';
import remarkRehype from 'remark-rehype';
import rehypeSlug from 'rehype-slug';
import rehypeStringify from 'rehype-stringify';
import rehypeHighlight from 'rehype-highlight';
import { visit } from 'unist-util-visit';

// Custom plugin to wrap <pre> in <details>
function rehypeCollapsibleCode() {
    return (tree: any) => {
        visit(tree, 'element', (node, index, parent) => {
            if (node.tagName === 'pre') {
                if (parent.tagName === 'details') return;
                const details = {
                    type: 'element',
                    tagName: 'details',
                    properties: { open: true, className: ['code-details'] },
                    children: [
                        {
                            type: 'element',
                            tagName: 'summary',
                            properties: {},
                            children: [{ type: 'text', value: 'Code' }]
                        },
                        node
                    ]
                };
                parent.children[index] = details;
            }
        });
    };
}

const postsDirectory = path.join(process.cwd(), 'public/posts');

export interface PostData {
    id: string;
    title: string;
    date: string;
    contentHtml?: string;
    headings?: { id: string; text: string; level: number }[];
    coverImage?: string; // Added coverImage
    [key: string]: any;
}

export function getAllPostIds() {
    if (!fs.existsSync(postsDirectory)) {
        return [];
    }

    // Recursive function to find all md files
    function getFiles(dir: string): string[] {
        const subdirs = fs.readdirSync(dir);
        const files = subdirs.map((subdir) => {
            const res = path.resolve(dir, subdir);
            return (fs.statSync(res).isDirectory()) ? getFiles(res) : res;
        });
        return Array.prototype.concat(...files);
    }

    const filePaths = getFiles(postsDirectory);

    return filePaths.filter(file => file.endsWith('.md')).map(file => {
        // Get relative path from postsDirectory to use as slug
        const relativePath = path.relative(postsDirectory, file);
        // Remove extension and replace path separators with something URL safe if needed
        // For now, we'll just use the filename without extension if it's unique enough,
        // or the full relative path. Let's use the filename for simplicity if flat,
        // or the directory name if it's index.md.
        // Given the "Notion export" usually creates "My Page/My Page.md" or "My Page.md"

        // Simple approach: Slug is the filename without extension
        const fileName = path.basename(file, '.md');
        return {
            params: {
                slug: fileName.replace(/\s+/g, '-').toLowerCase(), // approximate slug
            },
        };
    });
}

export async function getPostData(slug: string): Promise<PostData> {
    // Find the file that matches the slug
    function getFiles(dir: string): string[] {
        const subdirs = fs.readdirSync(dir);
        const files = subdirs.map((subdir) => {
            const res = path.resolve(dir, subdir);
            return (fs.statSync(res).isDirectory()) ? getFiles(res) : res;
        });
        return Array.prototype.concat(...files);
    }

    const allFiles = getFiles(postsDirectory);
    const file = allFiles.find(f => {
        const name = path.basename(f, '.md').replace(/\s+/g, '-').toLowerCase();
        return name === slug;
    });

    if (!file) {
        throw new Error(`Post not found for slug: ${slug}`);
    }

    const fileContents = fs.readFileSync(file, 'utf8');

    // Use gray-matter to parse the post metadata section
    const matterResult = matter(fileContents);

    // 1. Process Content to HTML with IDs
    const processedContent = await remark()
        .use(remarkRehype)
        .use(rehypeCollapsibleCode) // Wrap pre in details
        .use(rehypeHighlight) // Highlight code
        .use(rehypeSlug) // Adds id to headings
        .use(rehypeStringify)
        .process(matterResult.content);

    let contentHtml = processedContent.toString();

    // Custom replacements (Warnings/Notes) - Regex still works on HTML
    contentHtml = contentHtml.replace(
        /<blockquote>\s*<p>\[!WARNING\]\s*([\s\S]*?)<\/p>\s*<\/blockquote>/g,
        '<div class="warning-card">$1</div>'
    );
    contentHtml = contentHtml.replace(
        /<blockquote>\s*<p>\[!NOTE\]\s*([\s\S]*?)<\/p>\s*<\/blockquote>/g,
        '<div class="info-note">$1</div>'
    );

    // Rewrite relative image paths to include the folder path
    const relativeFolder = path.relative(postsDirectory, path.dirname(file)).replace(/\\/g, '/');
    const folderPrefix = relativeFolder ? `/posts/${relativeFolder}/` : '/posts/';

    contentHtml = contentHtml.replace(/src="([^"]+)"/g, (match, src) => {
        if (!src.startsWith('http') && !src.startsWith('/')) {
            return `src="${folderPrefix}${src}"`;
        }
        return match;
    });

    // 2. Extract Headings for TOC (Simple Regex approach)
    const headings: { id: string; text: string; level: number }[] = [];
    const headingRegex = /<h([1-3]) id="([^"]+)">([\s\S]*?)<\/h\1>/g;
    let match;
    while ((match = headingRegex.exec(contentHtml)) !== null) {
        headings.push({
            level: parseInt(match[1]),
            id: match[2],
            text: match[3].replace(/<[^>]*>/g, ''), // Strip inner HTML if any
        });
    }

    const title = matterResult.data.title || path.basename(file, '.md');
    const date = matterResult.data.date || new Date().toISOString().split('T')[0];

    return {
        id: slug,
        contentHtml,
        title,
        date,
        headings, // Return headings
        ...matterResult.data,
    };
}

export function getSortedPostsData() {
    if (!fs.existsSync(postsDirectory)) {
        return [];
    }

    function getFiles(dir: string): string[] {
        const subdirs = fs.readdirSync(dir);
        const files = subdirs.map((subdir) => {
            const res = path.resolve(dir, subdir);
            return (fs.statSync(res).isDirectory()) ? getFiles(res) : res;
        });
        return Array.prototype.concat(...files);
    }

    const allFiles = getFiles(postsDirectory).filter(f => f.endsWith('.md'));

    const allPostsData = allFiles.map((file) => {
        const fileContents = fs.readFileSync(file, 'utf8');
        const matterResult = matter(fileContents);
        const fileName = path.basename(file, '.md');
        const slug = fileName.replace(/\s+/g, '-').toLowerCase();

        // Logic to extract preview image
        let coverImage = matterResult.data.image;

        // Helper to resolve relative paths
        const resolveImagePath = (img: string) => {
            if (!img.startsWith('http') && !img.startsWith('/')) {
                const relativeFolder = path.relative(postsDirectory, path.dirname(file)).replace(/\\/g, '/');
                const folderPrefix = relativeFolder ? `/posts/${relativeFolder}/` : '/posts/';
                return `${folderPrefix}${img}`;
            }
            return img;
        };

        if (coverImage) {
            coverImage = resolveImagePath(coverImage);
        } else {
            // Try to find the first image in the content
            // Regex for ![alt](src)
            const imageRegex = /!\[.*?\]\((.*?)\)/;
            const match = imageRegex.exec(matterResult.content);
            if (match && match[1]) {
                coverImage = resolveImagePath(match[1]);
            }
        }

        return {
            id: slug,
            title: matterResult.data.title || fileName,
            date: matterResult.data.date || '2024-01-01',
            coverImage: coverImage || null,
            ...matterResult.data,
        };
    });

    return allPostsData.sort((a, b) => {
        if (a.date < b.date) {
            return 1;
        } else {
            return -1;
        }
    });
}
